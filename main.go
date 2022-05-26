package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"github.com/pkg/profile"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type certificate struct {
	issuer     string
	subject    string
	expireDate time.Time
	signDate   time.Time
	namespace  string
	secretName string
}

func main() {
	defer profile.Start().Stop()

	days := flag.Int("days", 30, "Number of days certificates will expiring")
	nonExpiring := flag.Bool("nonexpiring", false, "Display non-expiring certs or not")

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// gets the secret list
	secrets, err := clientset.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	parseSecret(*secrets, *clientset, *days, *nonExpiring)

}

func parseSecret(secrets v1.SecretList, clientset kubernetes.Clientset, days int, nonExpiring bool) {
	for _, secret := range secrets.Items {
		content, err := clientset.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			panic(err.Error())
		}
		if content.Type == "kubernetes.io/tls" || content.Type == "SecretTypeTLS" {
			certChain := string(content.Data["tls.crt"])
			if certChain == "" {
				panic("no tls.crt in the secret")
			}
			certs := getCert(certChain)
			for i := range certs {
				block, _ := pem.Decode([]byte(certs[i]))
				if block == nil {
					panic("failed to decode PEM block containing public key")
				}
				cert := parseCertificate(block.Bytes, content.Name, content.Namespace)
				finalOutput(cert, days, nonExpiring)
			}
		}
	}
}

func finalOutput(cert certificate, days int, nonExpiring bool) {
	today := time.Now()
	gapday := today.Add(time.Duration(days) * time.Hour).UTC()
	if cert.expireDate.Before(gapday) {
		fmt.Printf("!!WARN: The cert %s of project %s is expring in %v days\n", cert.secretName, cert.namespace, days)
		fmt.Println(cert.subject, cert.expireDate.String())
	} else if nonExpiring {
		fmt.Println(cert.secretName, cert.namespace, cert.issuer, cert.subject, cert.expireDate.String())
	}
}

func parseCertificate(block []byte, name, namespace string) certificate {
	certContent, err := x509.ParseCertificate(block)
	if err != nil {
		panic(err)
	}
	return certificate{subject: certContent.Subject.CommonName, issuer: certContent.Issuer.CommonName,
		expireDate: certContent.NotAfter, signDate: certContent.NotBefore, secretName: name, namespace: namespace}
}

func getCert(certChain string) []string {
	var certList []string
	certBeginMark, _ := regexp.Compile("-----BEGIN CERTIFICATE-----")
	certEndMark, _ := regexp.Compile("-----END CERTIFICATE-----")
	certStartList := certBeginMark.FindAllStringIndex(certChain, 10)
	certEndList := certEndMark.FindAllStringIndex(certChain, 10)
	for i := range certStartList {
		certStart := certStartList[i][0]
		certEnd := certEndList[i][1]
		certList = append(certList, certChain[certStart:certEnd])
	}
	return certList
}

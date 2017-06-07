using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Net;

namespace TlsMutualAuth.Controllers
{
    public class HomeController : Controller
    {
        string clientCertificateHeader = string.Empty;
        string serverCertificateHeader = string.Empty;
        string providerName = string.Empty;
        X509Certificate2 certificate = null;
        string errorString = string.Empty;
        bool isValidClientCert = false;

        public ActionResult Index()
        {
            string hostname = this.Request.ServerVariables.Get("HTTP_HOST");
            if(hostname.ToLower().Contains("azurewebsites.net"))
            { 
                TlsMutualAuthenticationAppService();
            }
            else
            {
                TlsMutualAuthenticationIIS();
            }
            return View();
        }

        public void TlsMutualAuthenticationIIS()
        {
            try
            {
                if (this.Request.ClientCertificate.Certificate != null)
                {
                    byte[] clientCertBytes = this.Request.ClientCertificate.Certificate;
                    certificate = new X509Certificate2(clientCertBytes);
                    ReadClientCertificate(certificate, clientCertBytes);
                }
            }
            catch(Exception ex1)
            {
                errorString = ex1.ToString();
            }
        }

        private bool IsValidClientCertificate()
        {
            return true;
        }

        public void TlsMutualAuthenticationAppService()
        {
            NameValueCollection headers = base.Request.Headers;
            //The X-ARR-ClientCert header contains the client certificate provided by the client
            clientCertificateHeader = headers["X-ARR-ClientCert"];
            try
            {
                if (!String.IsNullOrEmpty(clientCertificateHeader))
                {
                    byte[] clientCertBytes = Convert.FromBase64String(clientCertificateHeader);
                    certificate = new X509Certificate2(clientCertBytes);
                    ReadClientCertificate(certificate, clientCertBytes);
                }
            }
            catch (Exception ex)
            {
                errorString = ex.ToString();
            }
            finally
            {
                isValidClientCert = IsValidClientCertificate();
                if (!isValidClientCert) Response.StatusCode = 403;
                else Response.StatusCode = 200;
            }
        }

        public void ReadClientCertificate(X509Certificate2 certificate, byte[] clientCertBytes)
        {
            try
            {
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    //To make sure that a key container has been created, we are calling the SignData() method
                    byte[] encData = rsa.SignData(clientCertBytes, new SHA1CryptoServiceProvider());
                    CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
                    string str = keyInfo.ProviderName;
                    ViewBag.ProviderName = str;

                    ViewBag.ClientCertSubject = certificate.Subject;
                    ViewBag.ClientCertIssuer = certificate.Issuer;
                    ViewBag.ClientCertThumbprint = certificate.Thumbprint.ToString();
                    ViewBag.ClientCertIssueDate =  "     FROM :  " + certificate.NotBefore.ToUniversalTime().ToString("dd/MM/yyyy HH:mm");
                    ViewBag.ClientCertExpiryDate = "     TO   :  " + certificate.NotAfter.ToUniversalTime().ToString("dd/MM/yyyy HH:mm");
                    ViewBag.ClientCertVersion = certificate.Version;
                    ViewBag.PublicKeyAlgorithm = certificate.PublicKey.EncodedKeyValue.Oid.FriendlyName;
                    if (certificate.PublicKey.Key.KeyExchangeAlgorithm == null)
                    {
                        throw new NotSupportedException("Private key does not support key exchange");
                    }
                    ViewBag.KeyExchangeAlgorithm = certificate.PublicKey.Key.KeyExchangeAlgorithm;
                    ViewBag.KeySize = certificate.PublicKey.Key.KeySize;
                    ViewBag.SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName;
                    //Reading the optional field Enhanced Key Usage
                    X509EnhancedKeyUsageExtension ekuExtension = (X509EnhancedKeyUsageExtension)certificate.Extensions["Enhanced Key Usage"];
                    if (ekuExtension != null)
                    {
                        ViewBag.EkuExtension = ekuExtension.EnhancedKeyUsages;
                        ViewBag.EkuExtensionCount = ekuExtension.EnhancedKeyUsages.Count;
                    }
                    else
                    {
                        ViewBag.EkuExtension = "NULL";
                    }
                    //Reading the optional field Key Usage
                    X509KeyUsageExtension kuExtension = (X509KeyUsageExtension)certificate.Extensions["Key Usage"];
                    if (kuExtension != null)
                    {
                        ViewBag.KuExtension = kuExtension.KeyUsages;
                    }
                    else
                    {
                        ViewBag.KuExtension = "NULL";
                    }

                //X509Extension crlDistributionPoints = (X509Extension)certificate.Extensions["CRL Distribution Points"];
                //if(crlDistributionPoints!=null)
                //{
                //    byte[] crlBytes = crlDistributionPoints.RawData;

                //    AsnEncodedData asndata = new AsnEncodedData(crlDistributionPoints.Oid, crlDistributionPoints.RawData);

                //    X509Certificate2 x509 = new X509Certificate2();
                //    x509.Import(crlBytes);
                //    ViewBag.CrlDistributionPoints = crlDistributionPoints.Oid.Value.ToString();

                //}
                //else
                //{
                //    ViewBag.CrlDistributionPoints = "Not Available";
                //}

            }

            catch (Exception ex)
            {
                errorString = ex.ToString();
            }
        }

        //public void ServerCertificate()
        //{
        //    string hostname = this.Request.ServerVariables.Get("HTTP_HOST");
        //    string url = "https://" + hostname ;
        //    X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        //    certStore.Open(OpenFlags.ReadOnly);
        //    X509Certificate2Collection certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, "0BCBA0DA30D67E58F8DC6558A4B90B40168FC060", false);
        //    // Get the first cert with the thumbprint
        //    if (certCollection.Count > 0)
        //    {
        //        X509Certificate2 cert = certCollection[0];
        //        RequestResponse(url, cert);
        //    }
        //    certStore.Close();
        //}

        //private string RequestResponse(string pUrl, X509Certificate2 cert)
        //{
        //    HttpWebRequest webRequest = System.Net.WebRequest.Create(pUrl) as HttpWebRequest;
        //    webRequest.Method = "GET";
        //    webRequest.ServicePoint.Expect100Continue = false;
        //    webRequest.Timeout = 20000;
        //    webRequest.ClientCertificates.Add(cert);

        //    Stream responseStream = null;
        //    StreamReader responseReader = null;
        //    string responseData = "";
        //    try
        //    {
        //        WebResponse webResponse = webRequest.GetResponse();
        //        responseStream = webResponse.GetResponseStream();
        //        responseReader = new System.IO.StreamReader(responseStream);
        //        responseData = responseReader.ReadToEnd();
        //    }
        //    catch (Exception exc)
        //    {
        //        Response.Write("<br /><br />ERROR : " + exc.Message);
        //    }
        //    finally
        //    {
        //        if (responseStream != null)
        //        {
        //            responseStream.Close();
        //            responseReader.Close();
        //        }
        //    }
        //    return responseData;
        //}
    }
}
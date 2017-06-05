using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
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
        X509Certificate2 certificate = null;
        string errorString = string.Empty;
        bool isValidClientCert = false;
        public ActionResult Index()
        {
            TlsMutualAuthentication();
            return View();
        }
        private bool IsValidClientCertificate()
        {
            return true;
        }

        public void TlsMutualAuthentication()
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
                    ViewBag.ClientCertSubject = certificate.Subject;
                    ViewBag.ClientCertIssuer = certificate.Issuer;
                    ViewBag.ClientCertThumbprint = certificate.Thumbprint.ToString();
                    //ViewBag.ClientCertIssueDate = certificate.NotBefore.ToShortDateString() + " " + certificate.NotBefore.ToShortTimeString();
                    ViewBag.ClientCertIssueDate = certificate.NotBefore.ToUniversalTime().ToString("dd/MM/yyyy HH:mm");
                    ViewBag.ClientCertExpiryDate = certificate.NotAfter.ToUniversalTime().ToString("dd/MM/yyyy HH:mm");
                    ViewBag.ClientCertVersion = certificate.Version;
                    ViewBag.PublicKeyAlgorithm = certificate.PublicKey.EncodedKeyValue.Oid.FriendlyName;
                    ViewBag.KeyExchangeAlgorithm = certificate.PublicKey.Key.KeyExchangeAlgorithm;
                    ViewBag.KeySize = certificate.PublicKey.Key.KeySize;
                    ViewBag.SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName;

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

                    X509KeyUsageExtension kuExtension = (X509KeyUsageExtension)certificate.Extensions["Key Usage"];
                    if (kuExtension != null)
                    {
                        ViewBag.KuExtension = kuExtension.KeyUsages;
                    }
                    else
                    {
                        ViewBag.KuExtension = "NULL";
                    }
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

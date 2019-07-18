
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Helpers;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;

namespace BodySnifferProxy
{
    class ProxySniffer
    {
        private ProxyServer _proxyServer;
        private ExplicitProxyEndPoint _explicitEndPoint;
        public ProxySniffer()
        {
            this._proxyServer = new ProxyServer();
            this._explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Parse("10.21.104.251"), 8000, true);
        }
        public void SnifferStart()
        {
            

            //locally trust root certificate used by this proxy 
            _proxyServer.CertificateManager.TrustRootCertificate(true);

            //optionally set the Certificate Engine
            //Under Mono only BouncyCastle will be supported
            //proxyServer.CertificateManager.CertificateEngine = Network.CertificateEngine.BouncyCastle;

            _proxyServer.BeforeRequest += OnRequest;
            _proxyServer.BeforeResponse += OnResponse;
            _proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
            _proxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;


            //Fired when a CONNECT request is received
            //_explicitEndPoint.BeforeTunnelConnectRequest += OnBeforeTunnelConnectRequest;

            //An explicit endpoint is where the client knows about the existence of a proxy
            //So client sends request in a proxy friendly manner
            _proxyServer.AddEndPoint(_explicitEndPoint);
            _proxyServer.Start();

            //Transparent endpoint is useful for reverse proxy (client is not aware of the existence of proxy)
            //A transparent endpoint usually requires a network router port forwarding HTTP(S) packets or DNS
            //to send data to this endPoint
            var transparentEndPoint = new TransparentProxyEndPoint(IPAddress.Any, 8001, true)
            {
                //Generic Certificate hostname to use
                //when SNI is disabled by client
                GenericCertificateName = "google.com"
            };

            _proxyServer.AddEndPoint(transparentEndPoint);

            //proxyServer.UpStreamHttpProxy = new ExternalProxy() { HostName = "localhost", Port = 8888 };
            //proxyServer.UpStreamHttpsProxy = new ExternalProxy() { HostName = "localhost", Port = 8888 };

            foreach (var endPoint in _proxyServer.ProxyEndPoints)
                Console.WriteLine("Listening on '{0}' endpoint at Ip {1} and port: {2} ",
                    endPoint.GetType().Name, endPoint.IpAddress, endPoint.Port);

            //Only explicit proxies can be set as system proxy!
            // _proxyServer.SetAsSystemHttpProxy(_explicitEndPoint);
            // _proxyServer.SetAsSystemHttpsProxy(_explicitEndPoint);
        }

        public void SnifferStop()
        {
            _proxyServer.BeforeRequest -= OnRequest;
            _proxyServer.BeforeResponse -= OnResponse;
            _proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;
            _proxyServer.ClientCertificateSelectionCallback -= OnCertificateSelection;
            
            _proxyServer.Stop();
        }

        private async Task OnBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
        {
            string hostname = e.HttpClient.Request.RequestUri.Host;

            if (hostname.Contains("dropbox.com"))
            {
                //Exclude Https addresses you don't want to proxy
                //Useful for clients that use certificate pinning
                //for example dropbox.com
            }
        }

        public async Task OnRequest(object sender, SessionEventArgs e)
        {
            Console.WriteLine(e.HttpClient.Request.Url);

            ////read request headers
            var requestHeaders = e.HttpClient.Request.Headers;

            var method = e.HttpClient.Request.Method.ToUpper();
            if ((method == "POST" || method == "PUT" || method == "PATCH"))
            {
                //Get/Set request body bytes
                var bodyBytes = await e.GetRequestBody();
                e.SetRequestBody(bodyBytes);

                //Get/Set request body as string
                var bodyString = await e.GetRequestBodyAsString();
                Console.WriteLine(bodyString);
                e.SetRequestBodyString(bodyString);

                //store request 
                //so that you can find it from response handler 
                e.UserData = e.HttpClient.Request;
            }

            //To cancel a request with a custom HTML content
            //Filter URL
            if (e.HttpClient.Request.RequestUri.AbsoluteUri.Contains("google.com"))
            {
                e.Ok("<!DOCTYPE html>" +
                      "<html><body><h1>" +
                      "Website Blocked" +
                      "</h1>" +
                      "<p>Blocked by titanium web proxy.</p>" +
                      "</body>" +
                      "</html>");
            }
            //Redirect example
            if (e.HttpClient.Request.RequestUri.AbsoluteUri.Contains("wikipedia.org"))
            {
                e.Redirect("https://www.paypal.com");
            }
        }

        //Modify response
        public async Task OnResponse(object sender, SessionEventArgs e)
        {
            //read response headers
            var responseHeaders = e.HttpClient.Response.Headers;

            //if (!e.ProxySession.Request.Host.Equals("medeczane.sgk.gov.tr")) return;
            if (e.HttpClient.Request.Method == "GET" || e.HttpClient.Request.Method == "POST")
            {
                if (e.HttpClient.Response.StatusCode == (int)HttpStatusCode.OK)
                {
                    if (e.HttpClient.Response.ContentType != null && e.HttpClient.Response.ContentType.Trim().ToLower().Contains("text/html"))
                    {
                        var bodyBytes = await e.GetResponseBody();
                        e.SetResponseBody(bodyBytes);

                        var body = await e.GetResponseBodyAsString();
                        e.SetResponseBodyString(body);
                    }
                }
            }

            if (e.UserData != null)
            {
                //access request from UserData property where we stored it in RequestHandler
                var request = (Request)e.UserData;
            }

        }

        /// Allows overriding default certificate validation logic
        public Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            //set IsValid to true/false based on Certificate Errors
            if (e.SslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                e.IsValid = true;

            return Task.FromResult(0);
        }

        /// Allows overriding default client certificate selection logic during mutual authentication
        public Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
        {
            //set e.clientCertificate to override
            return Task.FromResult(0);
        }
    }
}

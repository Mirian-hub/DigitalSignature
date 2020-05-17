using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Services;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Web.DynamicData;

namespace DigitalSignature
{
    /// <summary>
    /// Summary description for DigitalSignatureService
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
    // [System.Web.Script.Services.ScriptService]
    public class DigitalSignatureService : System.Web.Services.WebService
    {
        protected string testUserPassword = "user123";
        protected string testDataGeneratedBySigature = "signature";

        [WebMethod]
        public string Signiture(string password, string sourceText)
        {
            if (testUserPassword != password)
                return "Password Nor Correct !";
            else
            {
                RSAEcnription rsa = new RSAEcnription();
                var encreptedSignature = rsa.EncriptText(testDataGeneratedBySigature);
                return sourceText + encreptedSignature;
            }
        }
    }

    public class RSAEcnription
    {
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        private RSACryptoServiceProvider sp = new RSACryptoServiceProvider(1024);
        public RSAEcnription()
        {
            this._privateKey = sp.ExportParameters(false);
            this._publicKey = sp.ExportParameters(true);
        }
        public string EncriptText(string text)
        {
            sp = new RSACryptoServiceProvider();
            sp.ImportParameters(_publicKey);
            var dataSource = Encoding.Unicode.GetBytes(text);
            var cyperText = sp.Encrypt(dataSource, false);
            return Convert.ToBase64String(cyperText);
        }
        public string Decript(string encodedText)
        {
            sp.ImportParameters(_privateKey);
            var dataInBytes = Convert.FromBase64String(encodedText);
            var decodedText = sp.Decrypt(dataInBytes, false);
            return Encoding.Unicode.GetString(decodedText);
        }

    }
}

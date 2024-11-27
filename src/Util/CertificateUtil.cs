using System;
#if NETSTANDARD || NET60 || NET70 || NET80
using System.Security;
#endif
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Util
{
    public static class CertificateUtil
    {
        public static X509Certificate2 Load(string path)
        {
            if (path.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(path));

#if NETSTANDARD || NET60 || NET70 || NET80
            return new X509Certificate2(path);
#else
            return X509CertificateLoader.LoadCertificateFromFile(path);
#endif
        }

        public static X509Certificate2 Load(string path, string password)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

#if NETSTANDARD || NET60 || NET70 || NET80
            return new X509Certificate2(path, password);
#else
            return X509CertificateLoader.LoadPkcs12FromFile(path, password);
#endif
        }

        public static X509Certificate2 Load(string path, string password, X509KeyStorageFlags keyStorageFlags)
        {
            if (path.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(path));
            if (password.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(password));

#if NETSTANDARD || NET60 || NET70 || NET80
            return new X509Certificate2(path, password, keyStorageFlags);
#else
            return X509CertificateLoader.LoadPkcs12FromFile(path, password, keyStorageFlags);
#endif
        }

        public static X509Certificate2 LoadBytes(string certificate)
        {
            if (string.IsNullOrWhiteSpace(certificate)) throw new ArgumentNullException(nameof(certificate));

            var encoding = new System.Text.UTF8Encoding();
#if NETSTANDARD || NET60 || NET70 || NET80
            return new X509Certificate2(encoding.GetBytes(certificate));
#else
            return X509CertificateLoader.LoadCertificate(encoding.GetBytes(certificate));
#endif
        }

        public static X509Certificate2 LoadBytes(string certificate, string password)
        {
            if (string.IsNullOrWhiteSpace(certificate)) throw new ArgumentNullException(nameof(certificate));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var encoding = new System.Text.UTF8Encoding();
#if NETSTANDARD || NET60 || NET70 || NET80
            return new X509Certificate2(encoding.GetBytes(certificate), password);
#else
            return X509CertificateLoader.LoadPkcs12(encoding.GetBytes(certificate), password);
#endif
        }

        public static X509Certificate2 LoadBytes(string certificate, string password, X509KeyStorageFlags keyStorageFlags)
        {
            if (string.IsNullOrWhiteSpace(certificate)) throw new ArgumentNullException(nameof(certificate));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var encoding = new System.Text.UTF8Encoding();
#if NETSTANDARD || NET60 || NET70 || NET80
            return new X509Certificate2(encoding.GetBytes(certificate), password, keyStorageFlags);
#else
            return X509CertificateLoader.LoadPkcs12(encoding.GetBytes(certificate), password);
#endif
        }

        public static X509Certificate2 Load(StoreName name, StoreLocation location, X509FindType type, string findValue)
        {
            if (findValue.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(findValue));

            var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var certificates = store.Certificates.Find(type, findValue, false);

                if (certificates.Count != 1)
                {
                    throw new InvalidOperationException($"Finding certificate with [StoreName: {name}, StoreLocation: {location}, X509FindType: {type}, FindValue: {findValue}] matched {certificates.Count} certificates. A unique match is required.");
                }

                return certificates[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}

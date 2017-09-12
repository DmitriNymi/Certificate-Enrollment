using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NEnrollment.Services.DelaySigning;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace NEnrollment.Tests
{
    [TestClass]
    public class DelayCsrProviderTest
    {
        private readonly bool _enableWritingToFile = false;

        DelayCsrProvider CreateSut()
        {
            return new DelayCsrProvider();
        }
        
        [TestMethod]
        public void ValidCsrWithoutPassword_Rsa_SignatureIsAppended()
        {
            var sut = CreateSut();

            const string signAlgorithm = "RSA";
            var keys = new Keys(signAlgorithm);

            // Create CSR
            var signatureAlgorithm = "SHA256withRSA";
            byte[] octetData = CreateCsr(keys.SignKeyPair, signatureAlgorithm);
            ByteArrayToFile(@"Rsa\csrWithoutPass.csr", octetData);

            // Append password to CSR
            byte[] csrWithPass = sut.AppendPassword(octetData, "some-text-1");
            ByteArrayToFile(@"Rsa\csrWithPass.csr", csrWithPass);

            // Calculate HASH
            var hashAlgorithm = CmsSignedGenerator.DigestSha256;
            byte[] hash = sut.BuildHash(csrWithPass, hashAlgorithm);

            // Sign using HASH
            byte[] signature = Sign(hash, signAlgorithm, hashAlgorithm, keys.SignKeyPair.Private);

            // Add signature to CSR
            byte[] csrSigned = sut.AppendSignature(csrWithPass, signature);
            ByteArrayToFile(@"Rsa\csrSigned.csr", csrSigned);

            // Just verify the signature matches CSR's public key + data,
            // public key should match the private key
            Verify(csrSigned);
            Verify2(csrSigned);
        }

        [TestMethod]
        public void ValidCsrWithoutPassword_Ecdsa_SignatureIsAppended()
        {
            var sut = CreateSut();

            const string signAlgorithm = "ECDSA";
            var keys = new Keys(signAlgorithm);

            // Create CSR
            var signatureAlgorithm = "SHA256withECDSA";
            byte[] octetData = CreateCsr(keys.SignKeyPair, signatureAlgorithm);
            ByteArrayToFile(@"Ecdsa\csrWithoutPass.csr", octetData);
            Verify(octetData);

            // Append password to CSR
            byte[] csrWithPass = sut.AppendPassword(octetData, "some-text-1");
            ByteArrayToFile(@"Ecdsa\csrWithPass.csr", csrWithPass);

            // Calculate HASH
            var hashAlgorithm = CmsSignedGenerator.DigestSha256;
            byte[] hash = sut.BuildHash(csrWithPass, hashAlgorithm);

            // Sign using HASH
            byte[] signature = Sign(hash, signAlgorithm, hashAlgorithm, keys.SignKeyPair.Private);

            // Add signature to CSR
            byte[] csrSigned = sut.AppendSignature(csrWithPass, signature);
            ByteArrayToFile(@"Ecdsa\csrSigned.csr", csrSigned);

            // Just verify the signature matches CSR's public key + data,
            // public key should match the private key

            //Verify2(csrSigned);
            Verify(csrSigned);
        }

        private byte[] CreateCsr(AsymmetricCipherKeyPair signingKeyPair, string signatureAlgorithm)
        {
            var key = signingKeyPair;

            Dictionary<DerObjectIdentifier, string> values = CreateSubjectValues("my common name");

            var subject = new X509Name(values.Keys.Reverse().ToList(), values);

            DerSet attributes = null;

            var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, key.Private);

            var pkcs10Csr = new Pkcs10CertificationRequest(
                signatureFactory,
                subject,
                key.Public,
                attributes,
                key.Private);

            byte[] derEncoded = pkcs10Csr.GetDerEncoded();

            //string stringEncoded = Convert.ToBase64String(derEncoded);
            //return stringEncoded;
            return derEncoded;
        }

        private Dictionary<DerObjectIdentifier, string> CreateSubjectValues(string commonName)
        {
            var values = new Dictionary<DerObjectIdentifier, string>
            {
                {X509Name.CN, commonName}, //domain name inside the quotes
                /*
                {X509Name.CN, csrSubject.CommonName}, //domain name inside the quotes
                {X509Name.OU, csrSubject.OrganizationalUnit},
                {X509Name.O, csrSubject.Organization}, //Organisation's Legal name inside the quotes
                {X509Name.L, csrSubject.City},
                {X509Name.ST, csrSubject.Country},
                {X509Name.C, csrSubject.State},
                */
            };

            // remove empty values
            var emptyKeys = values.Keys.Where(key => string.IsNullOrEmpty(values[key])).ToList();

            emptyKeys.ForEach(key => values.Remove(key));

            return values;
        }

        /// <summary>
        /// Calculate signature using signer algorithm for the defined has algorithm
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="signerAlgorithm"></param>
        /// <param name="hashAlgorithmOid">
        /// hash Algorithm Oid, for example:
        /// "2.16.840.1.101.3.4.2.1"
        /// </param>
        /// <param name="privateSigningKey">private key for signing</param>
        /// <returns></returns>
        public static byte[] Sign(byte[] hash, string signerAlgorithm, string hashAlgorithmOid, AsymmetricKeyParameter privateSigningKey)
        {
            
            var digestAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier(hashAlgorithmOid), DerNull.Instance);
            var dInfo = new DigestInfo(digestAlgorithm, hash);
            byte[] digest = dInfo.GetDerEncoded();

            ISigner signer = SignerUtilities.GetSigner(signerAlgorithm);
            signer.Init(true, privateSigningKey);
            signer.BlockUpdate(digest, 0, digest.Length);
            byte[] signature = signer.GenerateSignature();
            return signature;
            
/*  // Another way of signing
            if (signerAlgorithm == "RSA")
            {
                // convert private key from BouncyCastle to System.Security :
                RSA key = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)privateSigningKey);
                using (var cryptoServiceProvider = new RSACryptoServiceProvider())
                {
                    cryptoServiceProvider.ImportParameters(key.ExportParameters(true));

                    //
                    // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider
                    // to specify the use of SHA1 for hashing.
                    byte[] signedData = cryptoServiceProvider.SignHash(hash, hashAlgorithmOid);
                    return signedData;
                }
            }

            if (signerAlgorithm == "ECDSA")
            {
                // convert private key from BouncyCastle to System.Security :
                var bcKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateSigningKey);
                var pkcs8Blob = bcKeyInfo.GetDerEncoded();
                var key = CngKey.Import(pkcs8Blob, CngKeyBlobFormat.Pkcs8PrivateBlob);

                using (ECDsaCng cryptoServiceProvider = new ECDsaCng(key))
                {
                    cryptoServiceProvider.HashAlgorithm = CngAlgorithm.Sha256; //, hashAlgorithmOid);

                    byte[] signature = cryptoServiceProvider.SignHash(hash);
                    return signature;
                }
            }

            throw new NotImplementedException(signerAlgorithm);
*/
        }

        /// <summary>
        /// Verify signature using self verification of Pkcs10CertificationRequest
        /// </summary>
        /// <param name="csrSigned"></param>
        private void Verify(byte[] csrSigned)
        {
            Assert.IsNotNull(csrSigned);

            var csr = new Pkcs10CertificationRequest(csrSigned);

            bool isValid = csr.Verify();

            Assert.IsTrue(isValid, "Verification failed");
        }

        /// <summary>
        /// Verify signature using specified signer
        /// </summary>
        /// <param name="csrSigned"></param>
        private void Verify2(byte[] csrSigned)
        {
            var csr = new Pkcs10CertificationRequestDelaySigned(csrSigned);
            var sigBytes = csr.Signature.GetBytes();//.GetDerEncoded();
            var data = csr.GetDataToSign();
            AsymmetricKeyParameter publicSigningKey = csr.GetPublicKey();
            var signerAlgorithm = csr.SignatureAlgorithm.Algorithm.Id;

            var s = SignerUtilities.GetSigner(signerAlgorithm);
            s.Init(false, publicSigningKey);
            s.BlockUpdate(data, 0, data.Length);
            bool isValidSignature = s.VerifySignature(sigBytes);

            Assert.IsTrue(isValidSignature, "ECDSA verification failed");
        }

        private void ByteArrayToFile(string fileName, byte[] byteArray)
        {
            if (!_enableWritingToFile) return;

            try
            {
                fileName = @"C:\temp\delayCsrTest\" + fileName;
                new FileInfo(fileName).Directory?.Create();
                File.WriteAllBytes(fileName, byteArray);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                throw;
            }
        }
    }

    /// <summary>
    /// Helper that stores private and public key-pair as required for signing and verification of signature
    /// </summary>
    class Keys
    {
        private static readonly SecureRandom Rand;

        private readonly string _keyAlgorithm;

        private readonly KeyGenerationParameters _keyGenerationParameters;

        private readonly IAsymmetricCipherKeyPairGenerator _keyPairGenerator;

        private AsymmetricCipherKeyPair _signKeyPair;
        public AsymmetricCipherKeyPair SignKeyPair => _signKeyPair ?? (_signKeyPair = MakeKeyPair());

        static Keys()
        {
            try
            {
                Rand = new SecureRandom();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.ToString());
            }
        }

        public Keys(string keyAlgorithm)
        {
            _keyAlgorithm = keyAlgorithm;
            _keyGenerationParameters = CreateKeyGenerationParameters();
            _keyPairGenerator = CreateKeyPairGenerator();
        }

        private KeyGenerationParameters CreateKeyGenerationParameters()
        {
            SecureRandom random = Rand;
            //SecureRandom random = SecureRandom.GetInstance("SHA256PRNG");

            if (_keyAlgorithm == "RSA")
            {
                return new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), random, 2048, 25);
            }

            if (_keyAlgorithm == "ECDSA")
            {
                return new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random);
            }

            throw new NotSupportedException(_keyAlgorithm);
        }

        private IAsymmetricCipherKeyPairGenerator CreateKeyPairGenerator()
        {
            var keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator(_keyAlgorithm);
            keyPairGenerator.Init(_keyGenerationParameters);

            return keyPairGenerator;
        }

        public AsymmetricCipherKeyPair MakeKeyPair()
        {
            return _keyPairGenerator.GenerateKeyPair();
        }
    }
}

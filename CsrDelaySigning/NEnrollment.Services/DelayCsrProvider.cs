using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace NEnrollment.Services.DelaySigning
{
    public class DelayCsrProvider
    {
        /// <summary>
        /// append password to CSR: csrWithPassword = (csr, password)
        /// </summary>
        /// <param name="csr"></param>
        /// <param name="password"></param>
        /// <returns>CSR that  contains password</returns>
        public byte[] AppendPassword(byte[] csr, string password)
        {
            if (csr == null) throw new ArgumentNullException(nameof(csr));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            var originalCsr = new Pkcs10CertificationRequest(csr);

            CertificationRequestInfo cri = originalCsr.GetCertificationRequestInfo();

            DerSet attributesSet = AddPasswordAttribute(password, cri.Attributes);

            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(cri.SubjectPublicKeyInfo);

            string signatureAlgorithm = originalCsr.SignatureAlgorithm.Algorithm.Id;

            // build new CSR from original + password attribute
            var csrWithPassword =
                new Pkcs10CertificationRequestDelaySigned(signatureAlgorithm, cri.Subject, publicKey, attributesSet);

            // this signing key is not used for signing but here only to suppress exception thrown in ctor
            csrWithPassword.SignRequest(new byte[] { });

            var csrWithPasswordBytes = csrWithPassword.GetDerEncoded();

            return csrWithPasswordBytes;
        }

        private DerSet AddPasswordAttribute(string password, Asn1Set attributes)
        {
            if (attributes == null) attributes = new DerSet();

            List<AttributePkcs> attributesPkcs = attributes
                .OfType<DerSequence>()
                .Select(AttributePkcs.GetInstance)
                .ToList();

            bool hasPassword = attributesPkcs.Any(x => x.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtChallengePassword));
            if (hasPassword) throw new Exception("Cannot append password, already has password attribute in CSR.");

            AttributePkcs passwordAttribute = ChallengePasswordAttribute(password);

            attributesPkcs.Add(passwordAttribute);

            // ReSharper disable once CoVariantArrayConversion
            DerSet attributesSet = new DerSet(attributesPkcs.ToArray());
            return attributesSet;
        }

        private AttributePkcs ChallengePasswordAttribute(string password)
        {
            if (password == null) return null;

            Asn1EncodableVector attributeValues = new Asn1EncodableVector { new DerPrintableString(password) };

            return new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtChallengePassword, new DerSet(attributeValues));
        }

        /// <summary>
        /// Calculates hash (digest) of the given CSR using the specified hash algorithm OID
        /// </summary>
        /// <param name="csr">CSR without password</param>
        /// <param name="algorithm">digest algorithm OID, for example for SHA256 use: "2.16.840.1.101.3.4.2.1"</param>
        /// <returns>Hash of csr</returns>
        public byte[] BuildHash(byte[] csr, string algorithm)
        {
            var originalCsr = new Pkcs10CertificationRequestDelaySigned(csr);

            // parse CSR to Org.BouncyCastle.Pkcs.Pkcs10CertificationRequestDelaySigned
            //  requires CSR to have:
            // 1. Subject
            //      a. X509Name
            //      b. subject public key
            //      c. attributes
            //          c1. password - should be empty
            //          c2. extensions - should contain ... doesn't matter - don't touch
            // 2. SignatureAlgorithmId - keep as it is defined by user request
            // 3. SignBits of user for the given CSR

            // hash = function(csrWithPassword without signature/signature algorithm)
            // for some hash algorithms Hash may depend on a random number, 
            // thus giving different Hash every time it is calculated even for the same Data, PrivateKey

            byte[] dataToSign = originalCsr.GetDataToSign();

            //byte[] digest = DigestUtilities.CalculateDigest(CmsSignedGenerator.DigestSha256, dataToSign);
            byte[] digest = DigestUtilities.CalculateDigest(algorithm, dataToSign);

            return digest;
        }

        /// <summary>
        /// Creates new csr from given CSR + signature
        /// </summary>
        /// <param name="csr">CSR to be used for appending signature</param>
        /// <param name="signature">signature to be appended to CSR</param>
        /// <returns>new CSR with signature appended inside</returns>
        public byte[] AppendSignature(byte[] csr, byte[] signature)
        {
            if (csr == null) throw new ArgumentNullException(nameof(csr));

            var originalCsr = new Pkcs10CertificationRequestDelaySigned(csr);

            originalCsr.SignRequest(signature);

            byte[] csrBytes = originalCsr.GetDerEncoded();

            return csrBytes;
        }
    }
}

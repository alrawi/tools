from pyasn1.codec.der.decoder import decode
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful

MAX = 64  
class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('printableString', char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('universalString', char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('utf8String', char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('bmpString', char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('ia5String', char.IA5String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
        )

class AttributeValue(univ.Any): pass

class AttributeType(univ.ObjectIdentifier): pass

class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
        )

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
        )

class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
        )

class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.Any())
        )

class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', univ.BitString())
         )

class UniqueIdentifier(univ.BitString): pass

class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
        )

class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
        )

class CertificateSerialNumber(univ.Integer): pass

class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
        )

class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version('v1', tagSet=Version.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
        )

class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
        )

#
# PKCS#7 message syntax
#
# ASN.1 source from:
# http://www.trl.ibm.com/projects/xml/xss4j/data/asn1/grammars/pkcs7.asn
#
# Sample captures from:
# http://wiki.wireshark.org/SampleCaptures/
#

class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('values', univ.SetOf(componentType=AttributeValue()))
        )

class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeType', AttributeType()),
        namedtype.NamedType('attributeValue', AttributeValue())
        )

pkcs_7 = univ.ObjectIdentifier('1.2.840.113549.1.7')
data = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
signedData = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
envelopedData = univ.ObjectIdentifier('1.2.840.113549.1.7.3')
signedAndEnvelopedData = univ.ObjectIdentifier('1.2.840.113549.1.7.4')
digestedData = univ.ObjectIdentifier('1.2.840.113549.1.7.5')
encryptedData = univ.ObjectIdentifier('1.2.840.113549.1.7.6')

class ContentType(univ.ObjectIdentifier): pass

class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

class EncryptedContent(univ.OctetString): pass

class EncryptedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', ContentType()),
        namedtype.NamedType('contentEncryptionAlgorithm', ContentEncryptionAlgorithmIdentifier()),
        namedtype.OptionalNamedType('encryptedContent', EncryptedContent().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        )

class Version(univ.Integer): pass  # overrides x509.Version

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('encryptedContentInfo', EncryptedContentInfo())
        )

class DigestAlgorithmIdentifier(AlgorithmIdentifier): pass

class DigestAlgorithmIdentifiers(univ.SetOf):
    componentType = DigestAlgorithmIdentifier()

class Digest(univ.OctetString): pass

class ContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', ContentType()),
        namedtype.OptionalNamedType('content', univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        )

class DigestedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.NamedType('contentInfo', ContentInfo()),
        namedtype.NamedType('digest', Digest)
        )

class IssuerAndSerialNumber(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber())
        )

class KeyEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

class EncryptedKey(univ.OctetString): pass

class RecipientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
        )

class RecipientInfos(univ.SetOf):
    componentType = RecipientInfo()

class Attributes(univ.SetOf):
    componentType = Attribute()

class ExtendedCertificateInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('certificate', Certificate()),
        namedtype.NamedType('attributes', Attributes())
        )

class SignatureAlgorithmIdentifier(AlgorithmIdentifier): pass

class Signature(univ.BitString): pass

class ExtendedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extendedCertificateInfo', ExtendedCertificateInfo()),
        namedtype.NamedType('signatureAlgorithm', SignatureAlgorithmIdentifier()),
        namedtype.NamedType('signature', Signature())
        )

class ExtendedCertificateOrCertificate(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate', Certificate()),
        namedtype.NamedType('extendedCertificate', ExtendedCertificate().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
        )

class ExtendedCertificatesAndCertificates(univ.SetOf):
    componentType = ExtendedCertificateOrCertificate()

class SerialNumber(univ.Integer): pass

class CRLEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', SerialNumber()),
        namedtype.NamedType('revocationDate', useful.UTCTime())
        )

class TBSCertificateRevocationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('lastUpdate', useful.UTCTime()),
        namedtype.NamedType('nextUpdate', useful.UTCTime()),
        namedtype.OptionalNamedType('revokedCertificates', univ.SequenceOf(componentType=CRLEntry()))
        )

class CertificateRevocationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificateRevocationList', TBSCertificateRevocationList()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.BitString())
        )

class CertificateRevocationLists(univ.SetOf):
    componentType = CertificateRevocationList()

class DigestEncryptionAlgorithmIdentifier(AlgorithmIdentifier): pass

class EncryptedDigest(univ.OctetString): pass

class SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.OptionalNamedType('authenticatedAttributes', Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('digestEncryptionAlgorithm', DigestEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('encryptedDigest', EncryptedDigest()),
        namedtype.OptionalNamedType('unauthenticatedAttributes', Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        )

class SignerInfos(univ.SetOf):
    componentType = SignerInfo()

class SignedAndEnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('recipientInfos', RecipientInfos()),
        namedtype.NamedType('digestAlgorithms', DigestAlgorithmIdentifiers()),
        namedtype.NamedType('encryptedContentInfo', EncryptedContentInfo()),
        namedtype.OptionalNamedType('certificates', ExtendedCertificatesAndCertificates().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('crls', CertificateRevocationLists().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('signerInfos', SignerInfos())
        )

class EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('recipientInfos', RecipientInfos()),
        namedtype.NamedType('encryptedContentInfo', EncryptedContentInfo())
        )

class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.NamedType('digest', Digest())
        )

class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('digestAlgorithms', DigestAlgorithmIdentifiers()),
        namedtype.NamedType('contentInfo', ContentInfo()),
        namedtype.OptionalNamedType('certificates', ExtendedCertificatesAndCertificates().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('crls', CertificateRevocationLists().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('signerInfos', SignerInfos())
        )

class Data(univ.OctetString): pass



dictContentInfoMap = {
    (1, 2, 840, 113549, 1, 7, 1): Data(),
    (1, 2, 840, 113549, 1, 7, 2): SignedData(),
    (1, 2, 840, 113549, 1, 7, 3): EnvelopedData(),
    (1, 2, 840, 113549, 1, 7, 4): SignedAndEnvelopedData(),
    (1, 2, 840, 113549, 1, 7, 5): DigestedData(),
    (1, 2, 840, 113549, 1, 7, 6): EncryptedData()
    }

dictTypeMap = {
    (1,2,840,113549,1,1,1): "RSA Encryption",
    (1,2,840,113549,1,1,5): "SHA-1 with RSA Encryption",
    (1,2,840,113549,1,9,1): "e-mailAddress",
    (1,2,840,113549,1,9,2): "PKCS-9 unstructuredName",
    (1,2,840,113549,1,9,3): "contentType",
    (1,2,840,113549,1,9,4): "messageDigest",
    (1,2,840,113549,1,9,5): "Signing Time",
    (1,2,840,113549,1,9,6): "counterSignature",
    (1,2,840,113549,1,9,7): "Challenge Password",
    (1,2,840,113549,1,9,8): "PKCS-9 unstructuredAddress",
    (1,2,840,113549,1,9,9): "extendedCertificateAttributes",
    (1,3,6,1,4,1,311,2,1,4): "SPC_INDIRECT_DATA_OBJID",
    (1,3,6,1,4,1,311,2,1,11): "SPC_STATEMENT_TYPE_OBJID",
    (1,3,6,1,4,1,311,2,1,12): "SPC_SP_OPUS_INFO_OBJID",
    (1,3,6,1,4,1,311,2,1,15): "SPC_PE_IMAGE_DATA_OBJID",
    (1,3,6,1,4,1,311,2,1,27): "SPC_FINANCIAL_CRITERIA_OBJID",
    (1,3,6,1,5,5,7,1,1): "id-pe-authorityInfoAccess",
    (1,3,6,1,5,5,7,1,12): "id-pe-logotype",
    (1,3,14,3,2,26): "SHA-1 hash algorithm",
    (2,5,29,14): "Subject Key Identifier",
    (2,5,29,15): "Key Usage",
    (2,5,29,17): "Subject Alternative Name",
    (2,5,29,19): "Basic Constraints",
    (2,5,29,31): "CRL Distribution Points",
    (2,5,29,32): "Certificate Policies",
    (2,5,29,35): "Authority Key Identifier",
    (2,5,29,37): "Extended key usage",
    (2,5,4,3): "id-at-commonName",
    (2,5,4,6): "id-at-countryName",
    (2,5,4,7): "id-at-localityName",
    (2,5,4,8): "id-at-stateOrProvinceName",
    (2,5,4,10): "id-at-organizationName",
    (2,5,4,11): "id-at-organizationalUnitName",
    (2,16,840,1,113730,1,1): "Netscape certificate type"
}

def dump_content(cert=None):
    if cert==None or len(cert)<1:
        return
    (contentInfo, rest) = decode(cert, asn1Spec=ContentInfo())
    contentType = contentInfo.getComponentByName('contentType')
    (content, rest)= decode(contentInfo.getComponentByName('content'), asn1Spec=dictContentInfoMap[contentType])

    lstCerts = []
    try:
        for y in range(0, len(content['certificates'])):
            dictCert = {'issuer': {}, 'subject':{}, 'issueDate': 0, 'expiryDate': 0, 'serial': ""}

            try: dictCert['serial'] = str(content['certificates'][y]['certificate']['tbsCertificate']['serialNumber'])
            except: pass

            # subject info
            try:
                for x in content['certificates'][y]['certificate']['tbsCertificate']['subject'][0]:
                    if x[0][0] in dictTypeMap:
                        dictCert['subject'][dictTypeMap[x[0][0]]] = str(decode(x[0][1])[0])
                    else:
                        dictCert['subject'][str(x[0][0])] = str(decode(x[0][1])[0])
            except: pass

                    # issuer info
            try:
                for x in content['certificates'][y]['certificate']['tbsCertificate']['issuer'][0]:
                    if x[0][0] in dictTypeMap:
                        dictCert['issuer'][dictTypeMap[x[0][0]]] = str(decode(x[0][1])[0])
                    else:
                        dictCert['issuer'][str(x[0][0])] = str(decode(x[0][1])[0])
            except: pass

                    # time range
            try:
                dictCert['issueDate'] = str(content['certificates'][y]['certificate']['tbsCertificate']['validity']['notBefore']['utcTime'])
                dictCert['expiryDate'] = str(content['certificates'][y]['certificate']['tbsCertificate']['validity']['notAfter']['utcTime'])
            except: pass

            lstCerts.append(dictCert)

    except Exception as e:
        print e.message

    return lstCerts

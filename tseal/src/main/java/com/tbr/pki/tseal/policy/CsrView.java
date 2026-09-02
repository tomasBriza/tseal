package com.tbr.pki.tseal.policy;

import com.tbr.pki.tseal.csr.Oids;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class CsrView {

    final Map<ASN1ObjectIdentifier, String> subject = new LinkedHashMap<>();
    final Set<ASN1ObjectIdentifier> duplicateSubject = new LinkedHashSet<>();
    final List<String> dns = new ArrayList<>();
    final List<String> ip = new ArrayList<>();
    final List<String> email = new ArrayList<>();
    final Map<ASN1ObjectIdentifier, List<String>> otherNames = new LinkedHashMap<>();
    final Map<Integer, Integer> sanTagCounts = new LinkedHashMap<>();
    final Map<ASN1ObjectIdentifier, Extension> requestedExtensions = new LinkedHashMap<>();
    Duration requestedValidity;
    PublicKey publicKey;

    static PKCS10CertificationRequest parsePem(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("CSR PEM must be non-blank");
        }
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest csr) {
                return csr;
            }
            throw new IllegalArgumentException("PEM is not a certificate request");
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to parse CSR PEM", e);
        }
    }

    static CsrView parse(PKCS10CertificationRequest csr) {
        if (csr == null) {
            throw new IllegalArgumentException("CSR must be non-null");
        }
        CsrView view = new CsrView();
        parseSubject(view, csr.getSubject());
        parseExtensions(view, csr);
        try {
            view.publicKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();
        } catch (Exception e) {
            view.publicKey = null;
        }
        return view;
    }

    private static void parseSubject(CsrView view, X500Name subject) {
        if (subject == null) {
            return;
        }
        for (RDN rdn : subject.getRDNs()) {
            for (AttributeTypeAndValue atv : rdn.getTypesAndValues()) {
                ASN1ObjectIdentifier oid = atv.getType();
                String value = rdnString(atv);
                if (view.subject.containsKey(oid)) {
                    view.duplicateSubject.add(oid);
                } else {
                    view.subject.put(oid, value);
                }
            }
        }
    }

    private static String rdnString(AttributeTypeAndValue atv) {
        if (atv.getValue() instanceof ASN1String s) {
            return s.getString();
        }
        return atv.getValue().toString();
    }

    private static void parseExtensions(CsrView view, PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs == null) {
            return;
        }
        for (Attribute attr : attrs) {
            Extensions exts = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
            for (ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
                view.requestedExtensions.put(oid, exts.getExtension(oid));
            }
            parseSan(view, exts);
            parseRequestedValidity(view, exts);
        }
    }

    private static void parseSan(CsrView view, Extensions exts) {
        GeneralNames names = GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName);
        if (names == null) {
            return;
        }
        for (GeneralName gn : names.getNames()) {
            int tag = gn.getTagNo();
            view.sanTagCounts.merge(tag, 1, Integer::sum);
            switch (tag) {
                case GeneralName.dNSName -> view.dns.add(asn1String(gn));
                case GeneralName.iPAddress -> view.ip.add(ipString(gn));
                case GeneralName.rfc822Name -> view.email.add(asn1String(gn));
                case GeneralName.otherName -> {
                    OtherName on = OtherName.getInstance(gn.getName());
                    view.otherNames
                            .computeIfAbsent(on.getTypeID(), k -> new ArrayList<>())
                            .add(otherNameString(on));
                }
                default -> { }
            }
        }
    }

    private static void parseRequestedValidity(CsrView view, Extensions exts) {
        Extension ext = exts.getExtension(Oids.REQUESTED_VALIDITY);
        if (ext == null) {
            return;
        }
        long seconds = ASN1Integer.getInstance(exts.getExtensionParsedValue(Oids.REQUESTED_VALIDITY))
                .getValue()
                .longValueExact();
        view.requestedValidity = Duration.ofSeconds(seconds);
    }

    private static String asn1String(GeneralName gn) {
        if (gn.getName() instanceof ASN1String s) {
            return s.getString();
        }
        return gn.getName().toString();
    }

    private static String otherNameString(OtherName on) {
        if (on.getValue() instanceof ASN1String s) {
            return s.getString();
        }
        return on.getValue().toString();
    }

    private static String ipString(GeneralName gn) {
        byte[] octets = ASN1OctetString.getInstance(gn.getName()).getOctets();
        try {
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (UnknownHostException e) {
            return gn.getName().toString();
        }
    }
}

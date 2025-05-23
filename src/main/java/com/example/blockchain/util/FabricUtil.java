package com.example.blockchain.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.StreamSupport;

/**
 * Utility class for Fabric blockchain operations
 */
@Component
public class FabricUtil {

    /**
     * ECSignature record for managing ECDSA signatures in the format required by Fabric
     */
    public record ECSignature(ASN1Integer r, ASN1Integer s) {
        /**
         * Creates an ECSignature from a DER-encoded signature byte array
         */
        public static ECSignature fromBytes(final byte[] derSignature) throws GeneralSecurityException {
            try (ByteArrayInputStream inStream = new ByteArrayInputStream(derSignature);
                 ASN1InputStream asnInputStream = new ASN1InputStream(inStream)) {
                ASN1Primitive asn1 = asnInputStream.readObject();

                if (!(asn1 instanceof ASN1Sequence asn1Sequence)) {
                    throw new GeneralSecurityException(
                            "Invalid signature type: " + asn1.getClass().getTypeName());
                }

                List<ASN1Integer> signatureParts = StreamSupport.stream(asn1Sequence.spliterator(), false)
                        .map(ASN1Encodable::toASN1Primitive)
                        .filter(asn1Primitive -> asn1Primitive instanceof ASN1Integer)
                        .map(asn1Primitive -> (ASN1Integer) asn1Primitive)
                        .toList();
                if (signatureParts.size() != 2) {
                    throw new GeneralSecurityException(
                            "Invalid signature. Expected 2 values but got " + signatureParts.size());
                }

                return new ECSignature(signatureParts.get(0), signatureParts.get(1));
            } catch (IOException e) {
                // Should not happen reading from ByteArrayInputStream
                throw new GeneralSecurityException("Error processing signature", e);
            }
        }

        /**
         * Converts the ECSignature to DER-encoded byte array
         */
        public byte[] getBytes() {
            try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream()) {
                DERSequenceGenerator sequence = new DERSequenceGenerator(bytesOut);
                sequence.addObject(r);
                sequence.addObject(s);
                sequence.close();
                return bytesOut.toByteArray();
            } catch (IOException e) {
                // Should not happen writing to ByteArrayOutputStream
                throw new RuntimeException("Error encoding signature", e);
            }
        }
    }

    /**
     * Converts an object to byte array for Fabric transactions
     */
    public static byte[] objectToBytes(Object obj) throws IOException {
        // String conversion to the byte array
        if (obj instanceof String) {
            return ((String) obj).getBytes();
        }

        // For other types, you can use JSON serialization
        return obj.toString().getBytes();
    }
}

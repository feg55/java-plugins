package com.example.sbx;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class AppTest {
    // Independently obtained with openssl x509 -noout -fingerprint -sha256.
    private static final String CERT_SHA256 = "59def4fea17d784ee2ee9f63624eff61a1dc0f5a630fb11294340aeaceae953e";

    @Rule
    public TemporaryFolder temporary = new TemporaryFolder();

    @Test
    public void fingerprintMatchesOpenSslForPemAndCertificateChain() throws Exception {
        Path cert = copyResource("cert.pem", temporary.newFolder().toPath());
        String pem = Files.readString(cert);
        assertEquals(CERT_SHA256, App.certificateSha256(cert));

        Files.writeString(cert, "\r\n" + pem.replace("\n", "\r\n") + "\r\n" + pem);
        assertEquals(CERT_SHA256, App.certificateSha256(cert));
    }

    @Test
    public void hysteriaLinksCarryTheCertificatePinForBothImporterFormats() throws Exception {
        Path cert = copyResource("cert.pem", temporary.newFolder().toPath());
        String name = "Тест + server #1 & test";
        for (String address : List.of("192.0.2.1", "[2001:db8::1]")) {
            URI link = URI.create(App.generateHysteria2Link(address, name, cert));
            assertEquals("hysteria2", link.getScheme());
            assertTrue(link.getRawAuthority().contains("@" + address + ":"));
            assertEquals(name, link.getFragment());
            Map<String, String> query = queryParameters(link);
            assertEquals(CERT_SHA256, query.get("pinSHA256"));
            assertEquals(CERT_SHA256, query.get("pcs"));
            assertEquals("0", query.get("insecure"));
            assertEquals("0", query.get("allowInsecure"));
            assertEquals("h3", query.get("alpn"));
            assertFalse(query.containsKey("obfs"));
        }
    }

    @Test
    public void missingOrInvalidCertificateCannotProduceAnUnpinnedLink() throws Exception {
        Path cert = temporary.newFolder().toPath().resolve("cert.pem");
        assertThrows(IOException.class, () -> App.generateHysteria2Link("192.0.2.1", "test", cert));
        Files.writeString(cert, "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n");
        assertThrows(IOException.class, () -> App.generateHysteria2Link("192.0.2.1", "test", cert));
    }

    @Test
    public void certificateAndKeySurviveCleanupAndRestart() throws Exception {
        for (String runtimeName : List.of(".tmp", "custom-runtime")) {
            Path runtime = temporary.newFolder(runtimeName).toPath();
            Path cert = copyResource("cert.pem", runtime);
            Path key = copyResource("private.key", runtime);
            byte[] originalCert = Files.readAllBytes(cert);
            byte[] originalKey = Files.readAllBytes(key);
            String originalLink = App.generateHysteria2Link("192.0.2.1", "test", cert);
            Files.writeString(runtime.resolve("keypair.properties"), "reality-keypair");
            Files.writeString(runtime.resolve("sub.txt"), "subscription");

            for (int restart = 0; restart < 2; restart++) {
                Files.writeString(runtime.resolve("config.json"), "temporary config");
                Files.writeString(runtime.resolve("boot.log"), "temporary log");
                App.cleanupOldFiles(runtime);
                assertFalse(Files.exists(runtime.resolve("config.json")));
                assertFalse(Files.exists(runtime.resolve("boot.log")));
                App.ensureTlsCertificates(cert, key);

                Files.writeString(runtime.resolve("list.txt"), "temporary links");
                App.cleanupFiles(runtime, true);
                assertArrayEquals(originalCert, Files.readAllBytes(cert));
                assertArrayEquals(originalKey, Files.readAllBytes(key));
                assertEquals(originalLink, App.generateHysteria2Link("192.0.2.1", "test", cert));
                assertEquals("subscription", Files.readString(runtime.resolve("sub.txt")));
                assertEquals("reality-keypair", Files.readString(runtime.resolve("keypair.properties")));
                assertFalse(Files.exists(runtime.resolve("list.txt")));
            }
        }
    }

    @Test
    public void removingSubscriptionStillPreservesTlsIdentity() throws Exception {
        Path runtime = temporary.newFolder().toPath();
        Path cert = copyResource("cert.pem", runtime);
        Path key = copyResource("private.key", runtime);
        Files.writeString(runtime.resolve("sub.txt"), "subscription");
        App.cleanupFiles(runtime, false);
        assertEquals(CERT_SHA256, App.certificateSha256(cert));
        assertTrue(Files.exists(key));
        assertFalse(Files.exists(runtime.resolve("sub.txt")));
    }

    private static Path copyResource(String name, Path directory) throws IOException {
        Path target = directory.resolve(name);
        try (var input = AppTest.class.getResourceAsStream("/tls/" + name)) {
            if (input == null) throw new IOException("Missing test resource: " + name);
            Files.copy(input, target);
        }
        return target;
    }

    private static Map<String, String> queryParameters(URI uri) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String parameter : uri.getRawQuery().split("&")) {
            String[] pair = parameter.split("=", 2);
            values.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return values;
    }
}

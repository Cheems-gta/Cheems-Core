package win.cheems.core;

import android.content.Context;
import android.security.keystore.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

final class Vault {
  private static javax.crypto.SecretKey key() throws Exception {
    KeyStore store = KeyStore.getInstance("AndroidKeyStore");
    store.load(null);
    String alias = "cheems.nodes.v2";
    if (!store.containsAlias(alias)) {
      KeyGenerator g = KeyGenerator.getInstance("AES", "AndroidKeyStore");
      g.init(
          new KeyGenParameterSpec.Builder(
                  alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
              .build());
      g.generateKey();
    }
    return (javax.crypto.SecretKey) store.getKey(alias, null);
  }

  static void save(Context c, String value) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key());
    String v =
        Base64.getEncoder().encodeToString(cipher.getIV())
            + ":"
            + Base64.getEncoder()
                .encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    if (!c.getSharedPreferences("vault", 0).edit().putString("nodes", v).commit())
      throw new Exception("Save failed");
  }

  static String load(Context c) throws Exception {
    String v = c.getSharedPreferences("vault", 0).getString("nodes", "");
    if (v.isEmpty()) return "";
    String[] p = v.split(":");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.getDecoder().decode(p[0])));
    return new String(cipher.doFinal(Base64.getDecoder().decode(p[1])), StandardCharsets.UTF_8);
  }
}

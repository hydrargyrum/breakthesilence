/**
 * Copyright (C) 2011 Whisper Systems
 * Copyright (C) 2013 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package re.indigo.breakthesilence;

import java.io.IOException;
import java.io.FileReader;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.File;
import java.util.Properties;
import java.util.Base64;



public class MasterSecretUtil {

  public static final String UNENCRYPTED_PASSPHRASE  = "unencrypted";
  public static final String PREFERENCES_NAME        = "SecureSMS-Preferences";

  private static final String ASYMMETRIC_LOCAL_PUBLIC_DJB   = "asymmetric_master_secret_curve25519_public";
  private static final String ASYMMETRIC_LOCAL_PRIVATE_DJB  = "asymmetric_master_secret_curve25519_private";

  public class Context {

  }

  public static class InvalidPassphraseException extends Exception {
    public InvalidPassphraseException() {
      super();
      // TODO Auto-generated constructor stub
    }

    public InvalidPassphraseException(String detailMessage) {
      super(detailMessage);
      // TODO Auto-generated constructor stub
    }
  }

  public static class MasterSecret {
    public byte[] encryptionKey;
    public byte[] macKey;

    public MasterSecret(SecretKeySpec a, SecretKeySpec b) {
      encryptionKey = a.getEncoded();
      macKey = b.getEncoded();
    }
  }

  public static class InputData {
    public byte[] master_secret;
    public byte[] mac_salt;
    public int    passphrase_iterations;
    public byte[] encryption_salt;
    public String user_passphrase;
  }

  public static byte[][] split(byte[] input, int firstLength, int secondLength) {
    byte[][] parts = new byte[2][];

    parts[0] = new byte[firstLength];
    System.arraycopy(input, 0, parts[0], 0, firstLength);

    parts[1] = new byte[secondLength];
    System.arraycopy(input, firstLength, parts[1], 0, secondLength);

    return parts;
  }

  public static MasterSecret getMasterSecret(InputData context, String passphrase)
      throws InvalidPassphraseException, GeneralSecurityException, IOException
  {
    byte[] encryptedAndMacdMasterSecret = context.master_secret;
    byte[] macSalt                      = context.mac_salt;
    int    iterations                   = context.passphrase_iterations;
    byte[] encryptedMasterSecret        = verifyMac(macSalt, iterations, encryptedAndMacdMasterSecret, passphrase);
    byte[] encryptionSalt               = context.encryption_salt;
    byte[] combinedSecrets              = decryptWithPassphrase(encryptionSalt, iterations, encryptedMasterSecret, passphrase);
    byte[] encryptionSecret             = split(combinedSecrets, 16, 20)[0];
    byte[] macSecret                    = split(combinedSecrets, 16, 20)[1];

    return new MasterSecret(new SecretKeySpec(encryptionSecret, "AES"),
                            new SecretKeySpec(macSecret, "HmacSHA1"));
  }

  private static SecretKey getKeyFromPassphrase(String passphrase, byte[] salt, int iterations)
      throws GeneralSecurityException
  {
    PBEKeySpec keyspec    = new PBEKeySpec(passphrase.toCharArray(), salt, iterations);
    SecretKeyFactory skf  = SecretKeyFactory.getInstance("PBEWITHSHA1AND128BITAES-CBC-BC");
    return skf.generateSecret(keyspec);
  }

  private static Cipher getCipherFromPassphrase(String passphrase, byte[] salt, int iterations, int opMode)
      throws GeneralSecurityException
  {
    SecretKey key    = getKeyFromPassphrase(passphrase, salt, iterations);
    Cipher    cipher = Cipher.getInstance(key.getAlgorithm());
    cipher.init(opMode, key, new PBEParameterSpec(salt, iterations));

    return cipher;
  }

  private static byte[] encryptWithPassphrase(byte[] encryptionSalt, int iterations, byte[] data, String passphrase)
      throws GeneralSecurityException
  {
    Cipher cipher = getCipherFromPassphrase(passphrase, encryptionSalt, iterations, Cipher.ENCRYPT_MODE);
    return cipher.doFinal(data);
  }

  private static byte[] decryptWithPassphrase(byte[] encryptionSalt, int iterations, byte[] data, String passphrase)
      throws GeneralSecurityException, IOException
  {
    Cipher cipher = getCipherFromPassphrase(passphrase, encryptionSalt, iterations, Cipher.DECRYPT_MODE);
    return cipher.doFinal(data);
  }

  private static Mac getMacForPassphrase(String passphrase, byte[] salt, int iterations)
      throws GeneralSecurityException
  {
    SecretKey     key     = getKeyFromPassphrase(passphrase, salt, iterations);
    byte[]        pbkdf2  = key.getEncoded();
    SecretKeySpec hmacKey = new SecretKeySpec(pbkdf2, "HmacSHA1");
    Mac           hmac    = Mac.getInstance("HmacSHA1");
    hmac.init(hmacKey);

    return hmac;
  }

  private static byte[] verifyMac(byte[] macSalt, int iterations, byte[] encryptedAndMacdData, String passphrase) throws InvalidPassphraseException, GeneralSecurityException, IOException {
    Mac hmac        = getMacForPassphrase(passphrase, macSalt, iterations);

    byte[] encryptedData = new byte[encryptedAndMacdData.length - hmac.getMacLength()];
    System.arraycopy(encryptedAndMacdData, 0, encryptedData, 0, encryptedData.length);

    byte[] givenMac      = new byte[hmac.getMacLength()];
    System.arraycopy(encryptedAndMacdData, encryptedAndMacdData.length-hmac.getMacLength(), givenMac, 0, givenMac.length);

    byte[] localMac      = hmac.doFinal(encryptedData);

    if (Arrays.equals(givenMac, localMac)) return encryptedData;
    else                                   throw new InvalidPassphraseException("MAC Error");
  }

  private static byte[] macWithPassphrase(byte[] macSalt, int iterations, byte[] data, String passphrase) throws GeneralSecurityException {
    Mac hmac       = getMacForPassphrase(passphrase, macSalt, iterations);
    byte[] mac     = hmac.doFinal(data);
    byte[] result  = new byte[data.length + mac.length];

    System.arraycopy(data, 0, result, 0, data.length);
    System.arraycopy(mac,  0, result, data.length, mac.length);

    return result;
  }

  public static void main(String[] args) {
    Security.addProvider(new BouncyCastleProvider());

    if (args.length != 1) {
      System.err.println("Usage: breakthesilence.jar SILENCE_EXPORT_DIR_PATH");
      System.exit(64);
      return;
    }
    File propFile = new File(args[0]);

    Properties props = new Properties();
    try {
      props.load(new FileReader(propFile));
    } catch (IOException exc) {
      System.err.println("Cannot read properties from " + propFile);
      exc.printStackTrace(System.err);
      System.exit(74);
      return;
    }

    String userPassphrase = new String(System.console().readPassword("Password (leave empty if empty): "));
    if (userPassphrase.isEmpty()) {
      userPassphrase = UNENCRYPTED_PASSPHRASE;
    }

    InputData silProps = new InputData();
    silProps.passphrase_iterations = Integer.parseInt(props.getProperty("passphrase_iterations"));
    silProps.master_secret = Base64.getDecoder().decode(props.getProperty("master_secret"));
    silProps.mac_salt = Base64.getDecoder().decode(props.getProperty("mac_salt"));
    silProps.encryption_salt = Base64.getDecoder().decode(props.getProperty("encryption_salt"));
    silProps.user_passphrase = userPassphrase;

    MasterSecret sec;
    try {
       sec = getMasterSecret(silProps, silProps.user_passphrase);
    } catch (InvalidPassphraseException exc) {
      System.err.println("Invalid passphrase!");
      System.exit(65);
      return;
    } catch (GeneralSecurityException exc) {
      exc.printStackTrace(System.err);
      System.exit(1);
      return;
    } catch (IOException exc) {
      exc.printStackTrace(System.err);
      System.exit(74);
      return;
    }

    System.out.println("encryption_key = " + Base64.getEncoder().encodeToString(sec.encryptionKey));
    System.out.println("mac_key = " + Base64.getEncoder().encodeToString(sec.macKey));
  }
}

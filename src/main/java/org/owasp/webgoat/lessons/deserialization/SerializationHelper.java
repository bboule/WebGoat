/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SerializationHelper {

  private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
  private static final String SECRET_KEY = "WebGoatSecretKey1234567890123456"; // 32 bytes for HMAC-SHA256

  public static Object fromString(String s) throws IOException, ClassNotFoundException {
    byte[] data = Base64.getDecoder().decode(s);
    
    // Verify HMAC to ensure data integrity
    if (data.length < 32) {
      throw new SecurityException("Invalid data format - missing HMAC");
    }
    
    byte[] hmac = Arrays.copyOfRange(data, 0, 32);
    byte[] payload = Arrays.copyOfRange(data, 32, data.length);
    
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256");
      mac.init(keySpec);
      byte[] expectedHmac = mac.doFinal(payload);
      
      if (!Arrays.equals(hmac, expectedHmac)) {
        throw new SecurityException("HMAC verification failed - data may be tampered with");
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new SecurityException("HMAC verification error", e);
    }
    
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
    Object o = ois.readObject();
    ois.close();
    return o;
  }

  public static String toString(Serializable o) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(o);
    oos.close();
    byte[] payload = baos.toByteArray();
    
    // Generate HMAC for the payload
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256");
      mac.init(keySpec);
      byte[] hmac = mac.doFinal(payload);
      
      // Combine HMAC and payload
      ByteArrayOutputStream combined = new ByteArrayOutputStream();
      combined.write(hmac);
      combined.write(payload);
      
      return Base64.getEncoder().encodeToString(combined.toByteArray());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IOException("HMAC generation error", e);
    }
  }

  public static String show() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeLong(-8699352886133051976L);
    dos.close();
    byte[] longBytes = baos.toByteArray();
    return bytesToHex(longBytes);
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}

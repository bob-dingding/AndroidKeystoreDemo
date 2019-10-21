package com.zjt.androidkeystoredemo;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {


	KeyStore mKeyStore;
	String alias = "android";
	String encodeContent = "加密内容";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		initView();
		//获取秘钥库对象
		try {
			mKeyStore = KeyStore.getInstance("AndroidKeyStore");
			mKeyStore.load(null);
			//String encode = encryptText(alias, encodeContent);
			//String decodeContent = getSecreData(alias, encode);
		} catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	EditText etEncryptContent;
	Button btnEncrypt;
	TextView tvEncryptResult;
	Button btnDecrypt;
	TextView dectyptResult;
	Button btnClearAll;

	private void initView() {
		etEncryptContent = findViewById(R.id.et_encryptcontent);
		btnEncrypt = findViewById(R.id.btn_encript);
		tvEncryptResult = findViewById(R.id.tv_encryptresult);
		btnDecrypt = findViewById(R.id.btn_decript);
		dectyptResult = findViewById(R.id.tv_decryptResult);
		btnClearAll = findViewById(R.id.btn_celarall);


		btnEncrypt.setOnClickListener(this);
		btnDecrypt.setOnClickListener(this);
		btnClearAll.setOnClickListener(this);

	}


	/**
	 * 生成秘钥
	 * 采用加密算法为“AES / GCM / NoPadding”
	 *
	 * @param alias 别名是密钥在加解密过程中的一个识别连接，相当于我们在传递数据中的键值对中的键这样的一个作用。
	 */
	private SecretKey createSecretKey(final String alias) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {

		//创建得到一个密钥生成器KeyGenerator 的实例,参数是秘钥算法的名称和提供者名称
		final KeyGenerator keyGenerator = KeyGenerator
				.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
			//配置了密钥的别名，以及使用到的相关属性加密解密
			keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
					KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
					//setBlockModes()使我们确信仅指定可用于加密和解密的数据块模式中，如果使用的任何其他类型的块模式，它将被拒绝
					.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
					.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
					.build());
		}

		return keyGenerator.generateKey();
	}


	/**
	 * 数据加密，加密的实际过程是通过Cipher 类来完成的
	 *
	 * @param alias 别名
	 * @param textToEncrypt 要加密的内容
	 * @return
	 */
	byte[] encryptionIv;
	String encryptText(final String alias, final String textToEncrypt)
			throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		//得到了 Cipher 的实例,指定了加密的算法为 "AES/GCM/NoPadding
		final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		//直接初始化 Cipher 的实例ENCRYPT_MODE指定为加密模式，并传入我们的第一步创建的密钥
		cipher.init(Cipher.ENCRYPT_MODE, createSecretKey(alias));
		//getIV()方法返回新缓冲区中的初始化向量 (iv)。如果底层算法不使用 iv，或者 iv 尚未设置，则返回 nul。在创建随机 iv 的情况下，或者在基于密码加密或解密的上下文中（其中，iv 派生自用户提供的密码）此方法很有用
		encryptionIv = cipher.getIV();
		//直接调用 Cipher 的 doFinal 完成对数据的加密，doFinal方法返回一个字节数组，它是实际的加密文本
		byte[] encryption = cipher.doFinal(textToEncrypt.getBytes("UTF-8"));
		//我们直接 Base64 在编码一次返回string类型
		String encryptBase64 = Base64.encodeToString(encryption, Base64.DEFAULT);
		return encryptBase64;
	}


	/**
	 * 数据解密
	 *
	 * @return
	 */
	public String getSecreData(String alias, String encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeyException, UnrecoverableEntryException, KeyStoreException {
		//先获得 Cipher 的实例
		final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		//通过GCMParameterSpec 类来赋予 Cipher 初始化向量的参数,参数一是：初始化向量（IV），参数二是认证标签T的长度（以位为单位）
		final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
		//初始化 Cipher,DECRYPT_MODE为解密模式
		cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), spec);
		byte[] decodeContent = Base64.decode(encryptedData, Base64.DEFAULT);
		return new String(cipher.doFinal(decodeContent), "UTF-8");
	}


	/**
	 * 通过我们最初设定的别名识别对应的密钥
	 *
	 * @param alias
	 * @return
	 */
	private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
			UnrecoverableEntryException, KeyStoreException {
		return (SecretKey) mKeyStore.getKey(alias, null);
		//return (SecretKey) mKeyStore.getEntry(alias, null);
	}


	String decryptContent;

	@Override
	public void onClick(View v) {
		switch (v.getId()) {
			case R.id.btn_encript:
				String encryptContent = String.valueOf(etEncryptContent.getText());
				try {
					decryptContent = encryptText(alias, encryptContent);
					tvEncryptResult.setText("加密结果是:\n"+decryptContent);
					;
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} catch (NoSuchProviderException e) {
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				} catch (InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				} catch (BadPaddingException e) {
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
				}
				break;
			case R.id.btn_decript:
				try {
					String decryptContentResult = getSecreData(alias, decryptContent);
					dectyptResult.setText("解密结果是:\n"+decryptContentResult);
				} catch (NoSuchPaddingException e) {
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} catch (NoSuchProviderException e) {
					e.printStackTrace();
				} catch (InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				} catch (BadPaddingException e) {
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				} catch (UnrecoverableEntryException e) {
					e.printStackTrace();
				} catch (KeyStoreException e) {
					e.printStackTrace();
				}
				break;
			case R.id.btn_celarall:
				etEncryptContent.setText("");
				tvEncryptResult.setText("");
				dectyptResult.setText("");
				break;

		}
	}
}


package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.file.FileSystemLoopException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.imageio.stream.ImageOutputStreamImpl;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.RsaKemParameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.PKCS7ProcessableObject;
import org.bouncycastle.cms.PKCS7TypedStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;

import code.GuiException;
import gui.Constants;

public class MyCode extends x509.v3.CodeV3 {
	private KeyStore ks;
	private String password;
	
	private String selected=null;
	private Provider prov;
	private PKCS10CertificationRequest csr; 
	
	//KONSTRUKTOR
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		try {
			ks= KeyStore.getInstance("PKCS12");
			ks.load(null, null);
			password="sifra";
			
			Security.addProvider(new BouncyCastleProvider());
			prov = Security.getProvider("BC");
			
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
	}
	
	
	//POZIVA SE PRVA
	//UCITAVANJE LISTE SVIH ALIAS PAROVA KLJUCEVA/SERTIFIKATA IZ LOKALNOG SKLADISTA SERTIFIKATA U KOLEKCIJU TIPA ENUMERATIOR<STRING>
	@Override
	public Enumeration<String> loadLocalKeystore() {
		if(ks!=null) {
			try {
				return ks.aliases();
			} catch (KeyStoreException e) {
				e.printStackTrace();
				return null;
			}
		}
			
		return null;
	}
	
	
	//POZIVA SE KAD SE KLIKNE NA DUGME RESET LOCAL KEYSTORE 
	//BRISANJE CELOKUPNOG SADRZAJA LOKALNOG SKLADISTA SERTIFIKATA
	@Override
	public void resetLocalKeystore() {
		if(ks!=null) {
			try {
				ks.load(null,null);
			} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	//POZIVA SE KADA SE SELEKTUJE BILO KOJI PAR KLUCEVA/SERTIFIKATA U LISTIA ALIASA LOCAL KEYSTORA
	//TREBA DA UCITA PODATKE O PARU KLJUCEVA/SERTIFIKATU KOJI JE SACUVAN POD ALIASOM keypair_name IZ LOKALNOG SKLADISTA I PRIKAZE IH NA GUI-ju
	//POVRATNA VREDNOST -1-GRESKA, 0-SERTIFIKAT SACUVAN SA TIM ALIASOM NIJE POTPISAN, 1-U SLUCAJU DA JE POTPISAN, 2-U SLUCAJU DA JE TRUSTED
	@Override
	public int loadKeypair(String keypair_name) {
		selected=keypair_name;
		try {
			Key key=ks.getKey(keypair_name, password.toCharArray());
			X509Certificate certificate=(X509Certificate)ks.getCertificate(keypair_name); //dohvati sertifikat
			
			JcaX509CertificateHolder holder=new JcaX509CertificateHolder(certificate); //dohvati ko je holder tog sertifikata
			X500Name subj=holder.getSubject();	//
			X500Name issuer=holder.getIssuer(); //ko ga je potpisao
			
			if(issuer!=null) {
				super.access.setIssuer(issuer.toString()); //upisi ko ga je potpisao
				super.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName()); //i kojim algoritmom
			}
			
			super.access.setVersion(2);
			super.access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());
			super.access.setPublicKeyAlgorithm(certificate.getPublicKey().getAlgorithm());
			
			//ECPublicKey pk=(ECPublicKey) certificate.getPublicKey();
			//super.access.setPublicKeyParameter(pk.getParams().get);
			//super.access.setPublicKeyDigestAlgorithm();
			//super.access.setPublicKeyECCurve(pk.getParams().getCurve().toString());
			
			super.access.setNotAfter(certificate.getNotAfter());
			super.access.setNotBefore(certificate.getNotBefore());
			super.access.setSerialNumber(certificate.getSerialNumber().toString());
			String ser = certificate.getSerialNumber().toString();
			
			for(RDN rdn:subj.getRDNs()) {  //dohvatamo podatke o korsnuku
				AttributeTypeAndValue atv=rdn.getFirst();
				if(atv.getType().equals(BCStyle.CN)) {
					String CN = atv.getValue().toString();
					super.access.setSubjectCommonName(CN);
				}
				else if(atv.getType().equals(BCStyle.L)) {
					String L=atv.getValue().toString();
					super.access.setSubjectLocality(L);
				}
				else if(atv.getType().equals(BCStyle.C)) {
					String C=atv.getValue().toString();
					super.access.setSubjectCountry(C);
				}
				else if(atv.getType().equals(BCStyle.O)) {
					String O=atv.getValue().toString();
					super.access.setSubjectOrganization(O);
				}
				else if(atv.getType().equals(BCStyle.ST)) {
					String ST=atv.getValue().toString();
					super.access.setSubjectState(ST);
				}
				else if(atv.getType().equals(BCStyle.OU)) {
					String OU=atv.getValue().toString();
					super.access.setSubjectOrganizationUnit(OU);
				}
				else if(atv.getType().equals(BCStyle.SERIALNUMBER)) {
					ser = atv.getValue().toString();
				}
			}
			
			byte[] extensionValue1=certificate.getExtensionValue(Extension.keyUsage.getId());
			if(extensionValue1!=null) {
				boolean[] usage=certificate.getKeyUsage();
				super.access.setKeyUsage(usage);
			}
			
			byte[] extensionValue2=certificate.getExtensionValue(Extension.subjectDirectoryAttributes.getId());
			if(extensionValue2!=null) {
				ASN1Primitive sdaVal = JcaX509ExtensionUtils.parseExtensionValue(extensionValue2);
				
				SubjectDirectoryAttributes sdaAtr = SubjectDirectoryAttributes.getInstance(sdaVal);
				
				Vector<Attribute> attributes = sdaAtr.getAttributes();
				
				for(Attribute atr: attributes){
					if(atr.getAttrType().equals(BCStyle.DATE_OF_BIRTH)){
						access.setDateOfBirth(atr.getAttrValues().iterator().next().toString());
					}
					else if(atr.getAttrType().equals(BCStyle.PLACE_OF_BIRTH)){
						access.setSubjectDirectoryAttribute(0, atr.getAttrValues().iterator().next().toString());
					}
					else if(atr.getAttrType().equals(BCStyle.COUNTRY_OF_CITIZENSHIP)){
						access.setSubjectDirectoryAttribute(1, atr.getAttrValues().iterator().next().toString());
					}
					else if(atr.getAttrType().equals(BCStyle.GENDER)){
						access.setGender(atr.getAttrValues().iterator().next().toString());
					}
				}
			}
			
			byte[] extensionValue3=certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
			if(extensionValue3!=null) {
				List<String> usage=certificate.getExtendedKeyUsage();
				Iterator<String> iter=usage.iterator();
				boolean[] niz=new boolean[7];
				for(int i=0; i<7; i++)niz[i]=false;

				while(iter.hasNext()) {
					String identifier=iter.next();

					if(identifier.equals("2.5.29.37.0")) {
						niz[0]=true;
					}
					if(identifier.equals("1.3.6.1.5.5.7.3.1")) {
						niz[1]=true;
					}
					if(identifier.equals("1.3.6.1.5.5.7.3.2")) {
						niz[2]=true;
					}
					if(identifier.equals("1.3.6.1.5.5.7.3.3")) {
						niz[3]=true;
					}
					if(identifier.equals("1.3.6.1.5.5.7.3.4")) {
						niz[4]=true;
					}
					if(identifier.equals("1.3.6.1.5.5.7.3.8")) {
						niz[5]=true;
					}
					if(identifier.equals("1.3.6.1.5.5.7.3.9")) {
						niz[6]=true;
					}
				}
				super.access.setExtendedKeyUsage(niz);
								
				if(ks.isCertificateEntry(keypair_name))return 2; //trusted
				else if(!(new JcaX509CertificateHolder(certificate).getSubject().toString()
						.equalsIgnoreCase(new JcaX509CertificateHolder(certificate).getIssuer().toString())))  return 1;
			}	
			
		} catch (KeyStoreException | CertificateEncodingException | CertificateParsingException | IOException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	//POZIVA SE PRITISKOMA NA DUGME SAVEKEYPAIR
	//GENERISANJE I CUVANJE NOVOG PARA KLJUCEVA POD ALIASOM keypair_name U LOKALNO SKLADISTE SERTIFIKATA NA OSNOVU PODATAKA SA GUIJA
	//POVRATNA VREDNOST TRUE-USPESNO IZVRSENA, FALSE-GRESKA
	@Override
	public boolean saveKeypair(String keypair_name) {
		try {
			ECGenParameterSpec genSpec=new ECGenParameterSpec(super.access.getPublicKeyECCurve()); //dohvatimo unete podatke o krivi
			KeyPairGenerator kpgen=KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider()); //napravimo generator
			kpgen.initialize(genSpec);  //inicijalizujemo generator unetim podacima
			
			KeyPair pair=kpgen.generateKeyPair(); //generator mi napravi keypair
			PublicKey pu=pair.getPublic(); //dohvatim public key
			PrivateKey pr=pair.getPrivate(); //dohvatim private key
			
			X500NameBuilder nb=new X500NameBuilder(BCStyle.INSTANCE);
			nb.addRDN(BCStyle.CN, super.access.getSubjectCommonName());
			nb.addRDN(BCStyle.O, super.access.getSubjectOrganization());
			nb.addRDN(BCStyle.OU, super.access.getSubjectOrganizationUnit());
			nb.addRDN(BCStyle.L, super.access.getSubjectLocality());
			nb.addRDN(BCStyle.ST, super.access.getSubjectState());
			nb.addRDN(BCStyle.C, super.access.getSubjectCountry());
			X500Name subject=nb.build(); //dohvatim sve to i napravim
			X500Name issuer=subject;
			
			BigInteger serial = new BigInteger(super.access.getSerialNumber());
			Date NOT_BEFORE = super.access.getNotBefore();
			Date NOT_AFTER = super.access.getNotAfter();
			
			X509v3CertificateBuilder certbuilder = new JcaX509v3CertificateBuilder(issuer, serial, NOT_BEFORE, NOT_AFTER, subject, pu);
			
			
			
			
			//KEYUSAGE
			boolean[] keyusage = super.access.getKeyUsage();
			int usage = 0;
			if (keyusage[0] == true)
				usage |= KeyUsage.digitalSignature;
			if (keyusage[1] == true)
				usage |= KeyUsage.nonRepudiation;
			if (keyusage[2] == true)
				usage |= KeyUsage.keyEncipherment;
			if (keyusage[3] == true)
				usage |= KeyUsage.dataEncipherment;
			if (keyusage[4] == true)
				usage |= KeyUsage.keyAgreement;
			if (keyusage[5] == true)
				usage |= KeyUsage.keyCertSign;
			if (keyusage[6] == true)
				usage |= KeyUsage.cRLSign;
			if (keyusage[7] == true)
				usage |= KeyUsage.encipherOnly;
			if (keyusage[8] == true)
				usage |= KeyUsage.decipherOnly;
			
			boolean ku_crit=super.access.isCritical(Constants.KU);

			KeyUsage keyUsage = new KeyUsage(usage);
			if (usage != 0) {
				certbuilder.addExtension(Extension.keyUsage, ku_crit, keyUsage);
			}
			
			
			
			//SUBJECT DIRECTORY ATTRIBUTES
			String dateOfBirth = access.getDateOfBirth();
			String placeOfBirth = access.getSubjectDirectoryAttribute(Constants.POB);
			String country = access.getSubjectDirectoryAttribute(Constants.COC);
			String gender = access.getGender();
			boolean sdaCritical = access.isCritical(Constants.SDA);
			
			Vector<Attribute> attributes = new Vector<Attribute>();
			
			Attribute dobAttribure = new Attribute(BCStyle.DATE_OF_BIRTH, new DLSet(new DirectoryString(dateOfBirth)));
			Attribute pobAttribure = new Attribute(BCStyle.PLACE_OF_BIRTH, new DLSet(new DirectoryString(placeOfBirth)));
			Attribute coAttribure = new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DLSet(new DirectoryString(country)));
			Attribute geAttribure = new Attribute(BCStyle.GENDER, new DLSet(new DirectoryString(gender)));
			
			attributes.addElement(dobAttribure);
			attributes.addElement(pobAttribure);
			attributes.addElement(coAttribure);
			attributes.addElement(geAttribure);
			
			certbuilder.addExtension(Extension.subjectDirectoryAttributes, sdaCritical, new SubjectDirectoryAttributes(attributes));
			
			
			
			
			//EXTENDED KEY USAGE
			boolean eku_crit=super.access.isCritical(Constants.EKU);
			
			boolean[] extkeyusage= super.access.getExtendedKeyUsage();
			Vector<KeyPurposeId> kpid= new Vector<>();
			int extusage=0;
			if(extkeyusage[0]==true) {
				kpid.add(KeyPurposeId.anyExtendedKeyUsage);
			}
			if(extkeyusage[1]==true) {
				kpid.add(KeyPurposeId.id_kp_serverAuth);
			}
			if(extkeyusage[2]==true) {
				kpid.add(KeyPurposeId.id_kp_clientAuth);
			}
			if(extkeyusage[3]==true) {
				kpid.add(KeyPurposeId.id_kp_codeSigning);
			}
			if(extkeyusage[4]==true) {
				kpid.add(KeyPurposeId.id_kp_emailProtection);
			}
			if(extkeyusage[5]==true) {
				kpid.add(KeyPurposeId.id_kp_timeStamping);
			}
			if(extkeyusage[6]==true) {
				kpid.add(KeyPurposeId.id_kp_OCSPSigning);
			}
			if(kpid.size()>0) {
				certbuilder.addExtension(Extension.extendedKeyUsage, eku_crit, new ExtendedKeyUsage(kpid));
			}
			
			ContentSigner sign= new JcaContentSignerBuilder(super.access.getPublicKeyDigestAlgorithm()).build(pr);
			X509CertificateHolder holder = certbuilder.build(sign);
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert;
			
			ks.setKeyEntry(keypair_name, pr, password.toCharArray(), chain);
			
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | OperatorCreationException | CertificateException | CertIOException | KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
	//PRITISKOM NA DUGME REMOVE KEYPAIR
	//METODA TREBA DA UKLONI PAR KLJUCAVA/SERTIFIKATA POD ALIASOM keypair_name IZ LOKALNOG SKLADISTA SERTIFIKATA 
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean removeKeypair(String arg0) {
		try {
			ks.deleteEntry(arg0);
			File file = new File("MyKeyStore.p12");
			if (file.exists()) {
				FileOutputStream outputStream = new FileOutputStream(file);
				ks.store(outputStream, password.toCharArray());
				outputStream.close();
			};
			return true;

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	//PRITISKOM NA DUGME Import .p12 
	//TREBA DA IZ FAJLA SA PUTANJOM FILE UCITA POSTOJECI PAR KLUCEVA KOJI JE SACUVAN U PKCS#12 FORMATU I ZASTICEN LOZINKOM PASSWORD 
	//I SACUVA GA U LOKALNO SKLADISTE SA ALAISOM keypair_name
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean importKeypair(String keypair_name, String path, String pass) {
		File file= new File(path);
		InputStream stream;
		try {
			stream = new FileInputStream(file);
			
			KeyStore importKeystore=KeyStore.getInstance("PKCS12");
			importKeystore.load(stream, pass.toCharArray());
			Key key=importKeystore.getKey(keypair_name, pass.toCharArray());
			Certificate[] certs=importKeystore.getCertificateChain(keypair_name); //the certificate chain for the corresponding public key

			ks.setKeyEntry(keypair_name, key, password.toCharArray(), certs);
			
			stream.close();
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException | UnrecoverableKeyException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	//PRITISKOM NA DUGME export .p12
	//TREBA DA SELECTOVANI POSTOJECI PAR KLJUCEVA KOJI JE U LOCAL KEYSTOREU SACUVAN POD ALIASOM keypair_name IZVEZE, U PKCS#12 FORMATU,
	//U FAJL NA PUTANJI FILE I ZASTITI LOZINKOM PASSWORD
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean exportKeypair(String keypair_name, String file, String pass) {
		try {
			file = file.endsWith(".p12") ? file : file + ".p12";
			FileOutputStream fos = new FileOutputStream(new File(file));
			
			KeyStore exportKeystore = KeyStore.getInstance("PKCS12");
			Certificate[] chain = ks.getCertificateChain(keypair_name);
			exportKeystore.load(null, null);
			
			Key key=ks.getKey(keypair_name, password.toCharArray()); //dohvati iz mog key stora taj kljuc			
			exportKeystore.setKeyEntry(keypair_name, key, pass.toCharArray(), chain);
			exportKeystore.store(fos, pass.toCharArray());
			
			fos.close();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	//######################################################################################
	//######################################################################################
	
	//PRITISKOM NA DUGME IMPORT CERTRIFICATE
	//TREBA DA IZ FAJLA SA PUTANJOM file UCITA POSTOJECI SERTIFIKAT I SACUVA GA U LOKALNO SKLADISTE SERTIFIKATA POD IMENOM keypair_name
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean importCertificate(String file, String keypair_name) {
		try {
			InputStream in=new FileInputStream(file);
			
			CertificateFactory cf= CertificateFactory.getInstance("X509", "BC");
			X509Certificate cert=(X509Certificate)cf.generateCertificate(in);
			ks.setCertificateEntry(keypair_name, cert);
			
			in.close();
		} catch (CertificateException | NoSuchProviderException | KeyStoreException | IOException e) {
			e.printStackTrace();
			return false;		
		}
		
		return true;
	}
	
	//PRITISKOM NA DUGME EXPORT CERTIFIKATE 
	//POSTOJECI, SELEKTVAN U LOCAL KEYSTORU POD ALIASOM keypait_name, SERTIFIKAT IZVEZE U FAJL NA PUTANJI fajl 
	//I KODIRA GA NA NACIN NAZNACEN VREDNOSCU PARAMETRA encoding(0-DER, 1-PEM), format-OZNACAVA DA LI JE PRITOM POTREBNO IZVESTI I CEO LANAC
	//SERTIFIKATA(0-HEAD ONLY, 1-ENTIRE CHAIN)
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
		try {
			
			if(format==0) {
				
				X509Certificate cert=(X509Certificate) ks.getCertificate(keypair_name);
				if(encoding==0) { //DER
					FileOutputStream fos= new FileOutputStream(file);
					byte[] derEnc=cert.getEncoded();
					fos.write(derEnc);
					fos.close();
				}
				
				else if(encoding==1) {	//PEM
					JcaPEMWriter pemWr= new JcaPEMWriter(new FileWriter(file));
					pemWr.writeObject(cert);
					pemWr.flush();
					pemWr.close();
				}
				
			}
			
			else if (format==1) {
				
				X509Certificate[] certChain=(X509Certificate[]) ks.getCertificateChain(keypair_name);
				
				 	//PEM
					JcaPEMWriter pemWr= new JcaPEMWriter(new FileWriter(file));
					
					for(int i=0; i<certChain.length; i++) {
						pemWr.writeObject(certChain[i]);
						pemWr.flush();
					}
					
					pemWr.close();
					
				
			} 
			
		} catch (KeyStoreException | IOException | CertificateEncodingException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
	//PRITISKOM NA DUGME EXPORT CSR
	//TREBA DA GENERISE ZAHTEV ZA POTPISIVANJEM CERTIFIKATA keypair_name, DA GA POTPSE ALGORITMOM algorithm, I SACUVA NA PUTANJU file
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@SuppressWarnings("deprecation")
	@Override
	public boolean exportCSR(String path, String keypair_name, String algorithm) {
		try {
			X509Certificate cert= (X509Certificate) ks.getCertificate(keypair_name);
			PrivateKey prkey=(PrivateKey) ks.getKey(keypair_name, password.toCharArray()); //private key
			
			ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(prkey); // signer algoritam

			X500Name subjName = new JcaX509CertificateHolder(cert).getSubject(); //dohvatamo ko je subject
			PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjName,cert.getPublicKey()); //pravimo csr builder, on prima subjectname i public key
			
			
			
			//dohvatamo sve extenzije koje postoje
			JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
			List<ASN1ObjectIdentifier> list = holder.getExtensionOIDs();
			ExtensionsGenerator extensionGen = new ExtensionsGenerator();
			int i = 0;
			while (i < list.size()) {
				extensionGen.addExtension(holder.getExtension(list.get(i)));
				i++;
			}
			csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionGen.generate());

			PKCS10CertificationRequest req=csrBuilder.build(signer);
			
			
			//exportovanje u fajl
			PEMWriter pw= new PEMWriter(new FileWriter(path));
			pw.writeObject(req);
			pw.flush();
			pw.close();
			
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | OperatorCreationException | CertificateEncodingException | IOException e) {
			e.printStackTrace();
			return false;
		}
	
		return true;
	}
	
	//PRITISKOM NA DUGME SIGN CSR
	//TREBA DA UCITA ZAHTEV ZA POTPISIVANJE SELEKTOVANOG SERTIFIKATA IZ FAJLA file
	//POVRATNA VREDNOST JE INFORMACIJA O PODNOSIOCU ZAHTEVA 
	@Override
	public String importCSR(String path) {
		String ret="";
		try {
			FileInputStream fis = new FileInputStream(path);
			InputStreamReader isr= new InputStreamReader(fis);
			PEMParser pr= new PEMParser(isr);
			PKCS10CertificationRequest csr= (PKCS10CertificationRequest) pr.readObject();
			pr.close();
			
			X500Name subj=csr.getSubject();
						
			for(RDN rdn:subj.getRDNs()){
				AttributeTypeAndValue atv=rdn.getFirst();
				if(atv.getType().equals(BCStyle.CN)) {
					String CN = atv.getValue().toString();
					ret+="CN=" + CN + ",";
				}
				else if(atv.getType().equals(BCStyle.L)) {
					String L=atv.getValue().toString();
					ret+="L=" + L + ",";
				}
				else if(atv.getType().equals(BCStyle.C)) {
					String C=atv.getValue().toString();
					ret+="C=" + C + ",";
				}
				else if(atv.getType().equals(BCStyle.O)) {
					String O=atv.getValue().toString();
					ret+="O=" + O + ",";
				}
				else if(atv.getType().equals(BCStyle.ST)) {
					String ST=atv.getValue().toString();
					ret+="ST=" + ST + ",";
				}
				else if(atv.getType().equals(BCStyle.OU)) {
					String OU=atv.getValue().toString();
					ret+="OU=" + OU + ",";
				}				
			}
			ret+="SA=" + csr.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();
			this.csr=csr;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return ret;
	}

	//PRITISKOM NA DUGME SIGN 
	//TREBA DA POTPISE ALGORITMOM algorithm, SERTIFIKAT ZA KOJI JE KREIRAN CSR, PRIVATNIM KLJUCEM CA SERTIFIKATA KOJI JE U LOKALNOM 
	//SKLADISTU SACUVAN SA ALIASOM keypair_name, I SACUVA CA REPLY U PKCS#7 FORMATU U FAJL SA PUTANJOM file
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean signCSR(String path, String keypair_name, String algorithm) {
		try {
			String currentCert=super.access.getSubjectCommonName();
			X509Certificate potpisivac = (X509Certificate) ks.getCertificate(keypair_name);
			X509Certificate subjekat = (X509Certificate) ks.getCertificate(currentCert);
			
			BigInteger serial=new BigInteger(super.access.getSerialNumber());
			Date NOT_BEFORE = super.access.getNotBefore();
			Date NOT_AFTER = super.access.getNotAfter();
			
			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
					new JcaX509CertificateHolder(potpisivac).getSubject(),serial,
					NOT_BEFORE, NOT_AFTER, csr.getSubject(),
					subjekat.getPublicKey());
			
			
			
			//KEYUSAGE
			boolean[] keyusage = super.access.getKeyUsage();
			int usage = 0;
			if (keyusage[0] == true)
				usage |= KeyUsage.digitalSignature;
			if (keyusage[1] == true)
				usage |= KeyUsage.nonRepudiation;
			if (keyusage[2] == true)
				usage |= KeyUsage.keyEncipherment;
			if (keyusage[3] == true)
				usage |= KeyUsage.dataEncipherment;
			if (keyusage[4] == true)
				usage |= KeyUsage.keyAgreement;
			if (keyusage[5] == true)
				usage |= KeyUsage.keyCertSign;
			if (keyusage[6] == true)
				usage |= KeyUsage.cRLSign;
			if (keyusage[7] == true)
				usage |= KeyUsage.encipherOnly;
			if (keyusage[8] == true)
				usage |= KeyUsage.decipherOnly;
			
			boolean ku_crit=super.access.isCritical(Constants.KU);

			KeyUsage keyUsage = new KeyUsage(usage);
			if (usage != 0) {
				certBuilder.addExtension(Extension.keyUsage, ku_crit, keyUsage);
			}
			
			
			
			//SUBJECT DIRECTORY ATTRIBUTES
			String dateOfBirth = access.getDateOfBirth();
			String placeOfBirth = access.getSubjectDirectoryAttribute(Constants.POB);
			String country = access.getSubjectDirectoryAttribute(Constants.COC);
			String gender = access.getGender();
			boolean sdaCritical = access.isCritical(Constants.SDA);
			
			Vector<Attribute> attributes = new Vector<Attribute>();
			
			Attribute dobAttribure = new Attribute(BCStyle.DATE_OF_BIRTH, new DLSet(new DirectoryString(dateOfBirth)));
			Attribute pobAttribure = new Attribute(BCStyle.PLACE_OF_BIRTH, new DLSet(new DirectoryString(placeOfBirth)));
			Attribute coAttribure = new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DLSet(new DirectoryString(country)));
			Attribute geAttribure = new Attribute(BCStyle.GENDER, new DLSet(new DirectoryString(gender)));
			
			attributes.addElement(dobAttribure);
			attributes.addElement(pobAttribure);
			attributes.addElement(coAttribure);
			attributes.addElement(geAttribure);
			
			certBuilder.addExtension(Extension.subjectDirectoryAttributes, sdaCritical, new SubjectDirectoryAttributes(attributes));
			
			
			
			
			//EXTENDED KEY USAGE
			boolean eku_crit=super.access.isCritical(Constants.EKU);
			
			boolean[] extkeyusage= super.access.getExtendedKeyUsage();
			Vector<KeyPurposeId> kpid= new Vector<>();
			int extusage=0;
			if(extkeyusage[0]==true) {
				kpid.add(KeyPurposeId.anyExtendedKeyUsage);
			}
			if(extkeyusage[1]==true) {
				kpid.add(KeyPurposeId.id_kp_serverAuth);
			}
			if(extkeyusage[2]==true) {
				kpid.add(KeyPurposeId.id_kp_clientAuth);
			}
			if(extkeyusage[3]==true) {
				kpid.add(KeyPurposeId.id_kp_codeSigning);
			}
			if(extkeyusage[4]==true) {
				kpid.add(KeyPurposeId.id_kp_emailProtection);
			}
			if(extkeyusage[5]==true) {
				kpid.add(KeyPurposeId.id_kp_timeStamping);
			}
			if(extkeyusage[6]==true) {
				kpid.add(KeyPurposeId.id_kp_OCSPSigning);
			}
			if(kpid.size()>0) {
				certBuilder.addExtension(Extension.extendedKeyUsage, eku_crit, new ExtendedKeyUsage(kpid));
			}
			
			
			ContentSigner signer = new JcaContentSignerBuilder(algorithm).build((PrivateKey) ks.getKey(keypair_name, password.toCharArray()));
			X509Certificate signedCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

			Certificate[] chain = ks.getCertificateChain(keypair_name);
			X509Certificate[] newChain = new X509Certificate[chain.length + 1];
			newChain[0] = signedCert;
			for (int j = 0; j < newChain.length - 1; j++) {
				newChain[j + 1] = (X509Certificate) chain[j];
			}
			
			//PROVERA VALIDNOSTI I VERIFIKACIJA
			for(int i=0; i<newChain.length-1; i++) {
				newChain[i].checkValidity();
				newChain[i].verify(newChain[i+1].getPublicKey());
			}
			newChain[newChain.length-1].verify(newChain[newChain.length-1].getPublicKey());
			
			List<Certificate> certlist = new ArrayList<Certificate>();
	        for (int i = 0; i < newChain.length; i++) {
	            certlist.add(newChain[i]);
	        }
	        Store certstore = new JcaCertStore(certlist);

	        CMSSignedDataGenerator gen= new CMSSignedDataGenerator();
	        gen.addCertificates(certstore);
	        
	        CMSProcessableByteArray msg = new CMSProcessableByteArray("Hello World".getBytes());

	        CMSSignedData cms= gen.generate(msg, true);
	        	        
			PEMWriter pw= new PEMWriter(new FileWriter(path));
			pw.writeObject(cms.toASN1Structure());
			pw.flush();
			pw.close();
			
			return true;
		} catch (KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | OperatorCreationException | IOException | CMSException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
			e.printStackTrace();
			return false;
		} 
	}

	
	//PRITISKOM NA DUGME IMPORT CA REPLY 
	//TREBA DA IZ FAJLA NA PUTANJI file UCITA CA REPLY ZA PAR KLJUCEVA KOJI JE SACUVAN U LOKLNOM SKLADISTU SERTIFIKATA POD ALIASOM keypair_name
	//POVRATNA VREDNOST TRUE-USPEH, FALSE-GRESKA
	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			FileInputStream fis = new FileInputStream(file);

			CertificateFactory cf= CertificateFactory.getInstance("X509");
			Collection<X509Certificate> col= (Collection<X509Certificate>) cf.generateCertificates(fis);
			
			X509Certificate[] chain= new X509Certificate[col.size()];
			Iterator iter=col.iterator();
			
			for(int i=0; i<chain.length; i++) {
				chain[i]=(X509Certificate) iter.next();
			}
			
			ks.setKeyEntry(keypair_name, ks.getKey(keypair_name, password.toCharArray()),password.toCharArray(), chain);

			
		} catch (IOException | CertificateException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	
	//######################################################################
	//#####################################################################
	
	//TREBA DA ISPITA DA LI JE IZABRANI SERTIFIKAT KOJI JE U LOKALNOM SKLADISTU SERTIFIKATA SACUVAN POD ALIASON keypair_name
	//SERTIFIKACION AUTORITET KOJI MOZE DA POTPISUJE DRUGE SERTIFIKATE
	//POVRATNA VREDNOST FALSE OZNACAVA DA SERTIFIKAT NIJE CA
	@Override
	public boolean canSign(String keypair_name) {
		boolean i;
		try {
			X509Certificate certificate=(X509Certificate) ks.getCertificate(keypair_name);
			i=super.access.getKeyUsage()[5];
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		if(i==true)return true;
		else return false;
	}
	
	//TREBA DA VRATI PODATKE O VLASNIKU IZABRANOG SERTIFIKATA KOJI JE U LOKALNOM SKLADISTU SERTIFIKATA SACUVAN POD ALIASOM keypair_name
	//POVRATNA VREDNOST TREBA DA MU BUDE U FORMATU  ATTRIBUTE=VALUE[,ATTRIBUTE=VALUE] GDE JE ATTRIBUTE VREDNOST IZ SLEDECEG SKUPA {C, S, L, O, OU, CN, SA}
	@Override
	public String getSubjectInfo(String keypair_name) {
		String ret="";
		try {
			X509Certificate certificate=(X509Certificate) ks.getCertificate(keypair_name);
			JcaX509CertificateHolder holder=new JcaX509CertificateHolder(certificate); //dohvati ko je holder tog sertifikata
			X500Name subj=holder.getSubject();
			
			for(RDN rdn:subj.getRDNs()) {  //dohvatamo podatke o korsnuku
				AttributeTypeAndValue atv=rdn.getFirst();
				if(atv.getType().equals(BCStyle.CN)) {
					String CN = atv.getValue().toString();
					ret+="CN=" + CN + ",";
				}
				else if(atv.getType().equals(BCStyle.L)) {
					String L=atv.getValue().toString();
					ret+="L=" + L + ",";
				}
				else if(atv.getType().equals(BCStyle.C)) {
					String C=atv.getValue().toString();
					ret+="C=" + C + ",";
				}
				else if(atv.getType().equals(BCStyle.O)) {
					String O=atv.getValue().toString();
					ret+="O=" + O + ",";
				}
				else if(atv.getType().equals(BCStyle.ST)) {
					String ST=atv.getValue().toString();
					ret+="ST=" + ST + ",";
				}
				else if(atv.getType().equals(BCStyle.OU)) {
					String OU=atv.getValue().toString();
					ret+="OU=" + OU + ",";
				}
			}
			ret+="SA" + "=" + certificate.getSigAlgName();
			
		} catch (KeyStoreException | CertificateEncodingException e) {
			e.printStackTrace();
		}
		return ret;
	}
	
	//TREBA DA VRATI PODATKE O ALGORITMU KOJI JE KORISCEN ZA GENERISANJE PARA KLJUCEVA IZABRANOG SERTIFIKATA 
	//KOJI JE U LOKALNOM SKLADISTU SERTIFIKATA SACUVAN POD ALIASOM keypair_name
	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		String ret=null;
		try {
			X509Certificate certificate=(X509Certificate) ks.getCertificate(keypair_name);
			ret=certificate.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return ret;
	}

	//IME KRIVE IZABRANOG SERTIFIKATA KOJI JE U LOKALNOM SKLADISTU SERTIFIKATA SACUVAN POD ALIASOM keypair_name
	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		String ret=null;
		X509Certificate certificate=null;
		try {
			certificate=(X509Certificate) ks.getCertificate(keypair_name);
			ECPublicKey pk=(ECPublicKey) certificate.getPublicKey();
			ret=pk.getParams().toString();
		} catch(ClassCastException ce){
			RSAPublicKey rs=(RSAPublicKey) certificate.getPublicKey();
			ret=Integer.toString(rs.getModulus().bitLength());
		}
		  catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return ret;
	}


}

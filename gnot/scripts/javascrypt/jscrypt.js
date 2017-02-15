var loadTime = (new Date()).getTime();
var key;
var prng;
function setKey() {
	if (document.key.keytype[0].checked) {
		var s = encode_utf8(document.key.text.value);
		var i,
		kmd5e,
		kmd5o;
		if (s.length == 1) {
			s += s;
		}
		md5_init();
		for (i = 0; i < s.length; i += 2) {
			md5_update(s.charCodeAt(i));
		}
		md5_finish();
		kmd5e = byteArrayToHex(digestBits);
		md5_init();
		for (i = 1; i < s.length; i += 2) {
			md5_update(s.charCodeAt(i));
		}
		md5_finish();
		kmd5o = byteArrayToHex(digestBits);
		var hs = kmd5e + kmd5o;
		key = hexToByteArray(hs);
		hs = byteArrayToHex(key);
	} else {
		var s = document.key.text.value;
		var hexDigits = "0123456789abcdefABCDEF";
		var hs = "",
		i,
		bogus = false;
		for (i = 0; i < s.length; i++) {
			var c = s.charAt(i);
			if (hexDigits.indexOf(c) >= 0) {
				hs += c;
			} else {
				bogus = true;
			}
		}
		if (bogus) {
			alert("Hata: hexadecimal anahtarda  hatalı karakter(ler).");
		}
		if (hs.length > (keySizeInBits / 4)) {
			alert("Uyarı: hexadecimal anahtar maksimum degere ulasti: " +
				(keySizeInBits / 4) + ". Anahtar kisaltildi.");
			document.key.text.value = hs = hs.slice(0, 64);
		} else {
			while (hs.length < (keySizeInBits / 4)) {
				hs += "0";
			}
		}
		key = hexToByteArray(hs);
	}
}

function Generate_seed() {
    var i, j, k = "";

    addEntropyTime();
    var seed = keyFromEntropy();

    var prng = new AESprng(seed);
    if (document.seed.keytype[0].checked) {
        //	Text key
        var charA = ("A").charCodeAt(0);

        for (i = 0; i < 12; i++) {
            if (i > 0) {
                k += "-";
            }
            for (j = 0; j < 5; j++) {
                k += String.fromCharCode(charA + prng.nextInt(25));
            }
        }
    } else {
        // Hexadecimal key
        var hexDigits = "0123456789ABCDEF";

        for (i = 0; i < 64; i++) {
            k += hexDigits.charAt(prng.nextInt(15));
        }
    }
    document.seed.text.value = k;
    delete prng;
}

function Generate_key() {
	var i,
	j,
	k = "";
	var i,
	j,
	k = "";
	addEntropyTime();
	var seed = keyFromEntropy();
	var prng = new AESprng(seed);
	if (document.key.keytype[0].checked) {
		var charA = ("A").charCodeAt(0);
		for (i = 0; i < 12; i++) {
			if (i > 0) {
				k += "-";
			}
			for (j = 0; j < 5; j++) {
				k += String.fromCharCode(charA + prng.nextInt(25));
			}
		}
	} else {
		var hexDigits = "0123456789ABCDEF";
		for (i = 0; i < 64; i++) {
			k += hexDigits.charAt(prng.nextInt(15));
		}
	}
	document.key.text.value = k;
	delete prng;
}
function Encrypt_text() {
	var v,
	i;
	var prefix = "##### doga.me/gnot #####\n",
	suffix = "##### doga.me/gnot #####\n";
	if (document.key.text.value.length == 0) {
		alert("Mesaji sifreleyebilmek icin bir anahtar giriniz.");
		return;
	}
	if (document.plain.text.value.length == 0) {
		alert("Sifrelenecek metin bulunamadi. Lutfen metin bolumune bir seyler yazin ya da yapistirin.");
		return;
	}
	document.cipher.text.value = "";
	setKey();
	addEntropyTime();
	prng = new AESprng(keyFromEntropy());
	var plaintext = encode_utf8(document.plain.text.value);
	md5_init();
	for (i = 0; i < plaintext.length; i++) {
		md5_update(plaintext.charCodeAt(i));
	}
	md5_finish();
	var header = "";
	for (i = 0; i < digestBits.length; i++) {
		header += String.fromCharCode(digestBits[i]);
	}
	i = plaintext.length;
	header += String.fromCharCode(i >>> 24);
	header += String.fromCharCode(i >>> 16);
	header += String.fromCharCode(i >>> 8);
	header += String.fromCharCode(i & 0xFF);
	var ct = rijndaelEncrypt(header + plaintext, key, "CBC");
	if (document.plain.encoding[0].checked) {
		v = armour_codegroup(ct);
	} else if (document.plain.encoding[1].checked) {
		v = armour_hex(ct);
	} else if (document.plain.encoding[2].checked) {
		v = armour_base64(ct);
	}
	document.cipher.text.value = prefix + v + suffix;
	delete prng;
}
function determineArmourType(s) {
	var kt,
	pcg,
	phex,
	pb64,
	pmin;
	pcg = s.indexOf(codegroupSentinel);
	phex = s.indexOf(hexSentinel);
	pb64 = s.indexOf(base64sent);
	if (pcg == -1) {
		pcg = s.length;
	}
	if (phex == -1) {
		phex = s.length;
	}
	if (pb64 == -1) {
		pb64 = s.length;
	}
	pmin = Math.min(pcg, Math.min(phex, pb64));
	if (pmin < s.length) {
		if (pmin == pcg) {
			kt = 0;
		} else if (pmin == phex) {
			kt = 1;
		} else {
			kt = 2;
		}
	} else {
		if (document.plain.encoding[0].checked) {
			kt = 0;
		} else if (document.plain.encoding[1].checked) {
			kt = 1;
		} else if (document.plain.encoding[2].checked) {
			kt = 2;
		}
	}
	return kt;
}
function Decrypt_text() {
	if (document.key.text.value.length == 0) {
		alert("Desifre edebilmeniz icin sifre anahtarini bilmeniz gerekiyor. Lutfen anahtari ilgili yere yazin.");
		return;
	}
	if (document.cipher.text.value.length == 0) {
		alert("Desifre edilecek sifreli metin yok. Lutfen sifreli metni ilgili yere yazin.");
		return;
	}
	document.plain.text.value = "";
	setKey();
	var ct = new Array(),
	kt;
	kt = determineArmourType(document.cipher.text.value);
	if (kt == 0) {
		ct = disarm_codegroup(document.cipher.text.value);
	} else if (kt == 1) {
		ct = disarm_hex(document.cipher.text.value);
	} else if (kt == 2) {
		ct = disarm_base64(document.cipher.text.value);
	}
	var result = rijndaelDecrypt(ct, key, "CBC");
	var header = result.slice(0, 20);
	result = result.slice(20);
	var dl = (header[16] << 24) | (header[17] << 16) | (header[18] << 8) | header[19];
	if ((dl < 0) || (dl > result.length)) {
		alert("Mesaj uzunlugu " + result.length + " eksik karakter.  " +
			dl + " karakter bekleniyor.");
		dl = result.length;
	}
	var i,
	plaintext = "";
	md5_init();
	for (i = 0; i < dl; i++) {
		plaintext += String.fromCharCode(result[i]);
		md5_update(result[i]);
	}
	md5_finish();
	for (i = 0; i < digestBits.length; i++) {
		if (digestBits[i] != header[i]) {
			alert("Mesaj bozuk veya eksik.");
			break;
		}
	}
	document.plain.text.value = decode_utf8(plaintext);
}

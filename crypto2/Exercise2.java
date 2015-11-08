// Copyright (c) 2015 Mateusz Pyzik, all rights reserved.
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

class Exercise2 {
	public static void main(String[] args) throws Exception {
		File file = new File("2.txt");
		Scanner scanner = new Scanner(file);
		String sndHalf = scanner.next();
		List<Integer> data = new ArrayList<>();
		while(scanner.hasNext())
			data.add(scanner.nextInt(2));
		scanner.close();
		byte[] ciphertext = new byte[data.size()];
		for(int i = 0; i < ciphertext.length; ++i)
			ciphertext[i] = data.get(i).byteValue();
		for(long fstHalf = args.length > 0 ? Long.parseLong(args[0]) : 0; fstHalf <= 0xffffffffl; ++fstHalf)
		{
			String key = Integer.toHexString((int) fstHalf) + sndHalf;
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "RC4");
			Cipher cipher = Cipher.getInstance("RC4");
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
			String message = new String(cipher.update(ciphertext));
			if((fstHalf & 0x0000ffff) == 0)
				System.out.println(fstHalf);
			if(message.matches("[a-zA-Z0-9 .?,!()@\"'%-+]+"))
			{
				System.out.printf("%s\n%s\n", key, message);
				return;
			}
		}
		System.out.println("FAILED");
	}
}

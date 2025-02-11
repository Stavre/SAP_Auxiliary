package Day03_HMACandPBKDF.src.ro.ase.ism.sap.day3;

public class Util {
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for(byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}
}

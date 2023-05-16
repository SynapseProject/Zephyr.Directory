using System;
using System.Collections.Generic;
using System.Text;

namespace Zephyr.Directory.Ldap
{
	public class GenericUtils
	{
		public static string BytesToHex(byte[] b)
		{
            string s = BitConverter.ToString(b);
            return "0x" + s.Replace("-", "");
        }

        public static byte[] HexToBytes(string s)
        {
            string source = s;
            List<byte> bytes = new List<byte>();

            if (s.StartsWith("0x"))
                source = s.Substring(2);

            for (int i=0; i<source.Length; i+= 2)
            {
                byte b = Convert.ToByte(source.Substring(i, 2), 16);
                bytes.Add(b);
            }

            return bytes.ToArray();
        }

        public static string PrintBytes(byte[] bytes)
        {
            if (bytes == null)
                return null;

            StringBuilder sb = new StringBuilder();
            foreach (byte b in bytes)
                sb.Append(b + " ");

            return sb.ToString().Trim();
        }

    }

}


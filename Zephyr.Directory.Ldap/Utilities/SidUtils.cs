using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Zephyr.Crypto;

namespace Zephyr.Directory.Ldap
{
    public class SidUtils
    {
        // Taken from Stack Overflow Solution
        // https://stackoverflow.com/questions/47209459/adding-all-users-sids-from-active-directory-in-c-sharp
        //
        //public static string ConvertByteToStringSid(Byte[] sidBytes)
        //{
        //    StringBuilder strSid = new StringBuilder();
        //    strSid.Append("S-");
        //    try
        //    {
        //        // Add SID revision.
        //        strSid.Append(sidBytes[0].ToString());
        //        // Next six bytes are SID authority value.
        //        if (sidBytes[6] != 0 || sidBytes[5] != 0)
        //        {
        //            string strAuth = String.Format
        //                ("0x{0:2x}{1:2x}{2:2x}{3:2x}{4:2x}{5:2x}",
        //                (Int16)sidBytes[1],
        //                (Int16)sidBytes[2],
        //                (Int16)sidBytes[3],
        //                (Int16)sidBytes[4],
        //                (Int16)sidBytes[5],
        //                (Int16)sidBytes[6]);
        //            strSid.Append("-");
        //            strSid.Append(strAuth);
        //        }
        //        else
        //        {
        //            Int64 iVal = (Int32)(sidBytes[1]) +
        //                (Int32)(sidBytes[2] << 8) +
        //                (Int32)(sidBytes[3] << 16) +
        //                (Int32)(sidBytes[4] << 24);
        //            strSid.Append("-");
        //            strSid.Append(iVal.ToString());

        //            // Get sub authority count...
        //            int iSubCount = Convert.ToInt32(sidBytes[7]);
        //            int idxAuth = 0;
        //            for (int i = 0; i < iSubCount; i++)
        //            {
        //                idxAuth = 8 + i * 4;
        //                UInt32 iSubAuth = BitConverter.ToUInt32(sidBytes, idxAuth);
        //                strSid.Append("-");
        //                strSid.Append(iSubAuth.ToString());
        //            }
        //        }
        //    }
        //    catch (Exception)
        //    {

        //    }
        //    return strSid.ToString();
        //}

        public static string ConvertByteToStringSid(Byte[] sidBytes)
        {
            StringBuilder str = new StringBuilder("S-");

            // Convert Revision
            str.Append((int)sidBytes[0] + "-");

            // Get Sub-Id Count
            int subIdCount = (sidBytes.Length - 8) / 4;

            // Convert Identifier Authority
            byte[] idBytes = new byte[8];
            Buffer.BlockCopy(sidBytes, 2, idBytes, 2, 6);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(idBytes);
            long l = BitConverter.ToInt64(idBytes);
            str.Append(l + "");

            // Convert Each Sub-Id (4 Bytes, Little Endian)
            for (int i=0; i<subIdCount; i++)
            {
                byte[] subIdBytes = new byte[8];
                int offset = 8 + (i * 4);
                Buffer.BlockCopy(sidBytes, offset, subIdBytes, 0, 4);
                if (!BitConverter.IsLittleEndian)
                    Array.Reverse(subIdBytes);
                l = BitConverter.ToInt64(subIdBytes);
                str.Append("-" + l);
            }


            return str.ToString();
        }

        public static byte[] ConvertStringSidToBytes(string sid)
        {
            List<byte> bytes = new List<byte>();

            string[] sidParts = sid.Split('-', StringSplitOptions.None);

            if (sidParts[0].ToUpper() != "S")
                throw new Exception($"String [{sid}] Is Not A Properly Formatted Security Identifier String.");

            // Convert Revision
            byte b = (byte)int.Parse(sidParts[1]);
            bytes.Add(b);

            // Convert Sub-Id Count
            b = (byte)(sidParts.Length - 3);
            bytes.Add(b);

            // Convert Identifier Authority
            byte[] barr = BitConverter.GetBytes(long.Parse(sidParts[2]));
            if (BitConverter.IsLittleEndian)
                Array.Reverse(barr);
            for (int i = (barr.Length - 6); i< barr.Length; i++)
                bytes.Add(barr[i]);

            // Convert Each Sub-Id (4 Bytes, Little Endian)
            for (int i=3; i< sidParts.Length; i++)
            {
                barr = BitConverter.GetBytes(long.Parse(sidParts[i]));
                if (!BitConverter.IsLittleEndian)
                    Array.Reverse(barr);
                for (int j = 0; j < barr.Length && j<4; j++)
                    bytes.Add(barr[j]);

            }


            return bytes.ToArray();
        }

        public static bool IsSid(string sid)
        {
            bool isSid = false;
            if (!String.IsNullOrWhiteSpace(sid))
            {
                try
                {
                    byte[] bytes = ConvertStringSidToBytes(sid);
                    string newSid = ConvertByteToStringSid(bytes);
                    isSid = sid.ToUpper() == newSid.ToUpper();
                }
                catch { }
            }

            return isSid;
        }

        public static bool IsSid(byte[] bytes)
        {
            bool isSid = false;
            if (bytes != null)
            {
                try
                {
                    string sid = ConvertByteToStringSid(bytes);
                    byte[] newBytes = ConvertStringSidToBytes(sid);
                    isSid = bytes.SequenceEqual(newBytes);
                }
                catch { }
            }

            return isSid;
        }

    }
}

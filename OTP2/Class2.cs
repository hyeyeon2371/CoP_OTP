using System;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

//DoHaeng Lee
namespace OTP2
{
    public class TOTP
    {
        public static void Main(string[] args)
        {

            string seed = "38364a303143513253344f52385857544d55524d";
            //string seed = "HA3EUMBRINITEUZUJ5JDQWCXKRGVKUSN";

            //string seed = "35494e564e454e554d3252414a4c5144323437555a3145463545544345454652";

            /*
            // 랜덤으로 만들어서 base32 인코딩 하기
            string AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789";
            int n = 32; // 길이 either 20 or 32
            Random random = new Random();
            string s = new string(Enumerable.Repeat(AlphaNumericString, n).Select(s => s[random.Next(s.Length)]).ToArray());
            //hexlify까지 해줘야 완성
            string otpkey = str2hex(s);
            otpkey = otpkey.ToLower();
            string seed = otpkey;
            */

            string userOtp = "42289048";

            int seconds = 60;
            int digit = 8;
            string algorithm = "SHA256";

            Boolean ans = VerifyOTP(userOtp, seed, seconds, digit, algorithm);
        }

        public static Boolean VerifyOTP(string userOtp, string seed, int seconds, int digit, string algorithm)
        {
            Boolean ans = false;

            //한 번 입력한 otp는 재입력 불가하게 할 거면 db랑 엮어서
            string alreadyUsed = "N";
            int j = 0;
            int arrLength = 0;

            //string usedORnot = "NONE";
            string usedORnot = "99857520|32477929"; //DB 없이 테스트 중
            // DB  사용 시
            //string usedORnot = getUsedOtp(site,user); //가져올 때 null이면 "NONE"으로 리턴하기

            if (!usedORnot.Equals("NONE"))
            {
                string[] strArr = usedORnot.Split('|');
                arrLength = strArr.Length;
                while (j < arrLength)
                {
                    if (userOtp.Equals(strArr[j]))
                    {
                        //Debug.WriteLine("strArr[" + j + "] : " + strArr[j]);
                        Console.WriteLine("ALREADY USED");
                        alreadyUsed = "Y";
                        break;
                    }
                    j++;
                }
            }

            if (alreadyUsed.Equals("N"))
            {
                int setMin = 2; // 앞뒤로 몇 분씩 허용할 건지
                long T0 = 0; // default=0   ->  T를 unix 시간으로 구했으니 이대로 0
                /*
                long X = 60; // defulat=30
                int digit = 8; // OTP 자릿수
                int alg = 2; // 알고리즘 방식
                */
                long X = Convert.ToInt64(seconds);

                long curMs = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                long current = curMs / 1000L;   // ms 에서 s로

                int length = setMin * 2 + 1;
                long[] timeArr = new long[length];
                int negMin = setMin * (-1);
                for (int i = 0; i < length; i++)
                {
                    timeArr[i] = current + (negMin * 60);
                    negMin++;
                }

                try
                {
                    for (int i = 0; i < timeArr.Length; i++)
                    {
                        long T = (timeArr[i] - T0) / X;
                        int Tint = (int)T;
                        string chkOtp = GenerateOTP(seed, Tint, digit, algorithm);
                        //Console.WriteLine(i + " : " + chkOtp);
                        if (userOtp.Equals(chkOtp))
                        {
                            ans = true;
                            break;
                        }
                    }
                }
                catch (Exception e)
                {
                    //Debug.WriteLine("Error : " + e);
                    Console.WriteLine("Error : " + e);
                }
            }

            if (ans == true)
            {
                string newUsed = usedORnot;
                if (newUsed.Equals("NONE"))
                    newUsed = "";
                j = 0;

                if (arrLength != 0)
                {
                    if (arrLength == 5)
                    {
                        newUsed.Substring(9);
                    }
                    newUsed = newUsed + "|";
                }
                newUsed += userOtp;
                //Debug.WriteLine("newUsed : " + newUsed);
                // DB 사용 시
                /*
                if(newUsed.Equals("NONE")) 
                    insertUsedOtp(site,user,newUsed);
                else
                    updateUsedOtp(site,user,newUsed);
                */
            }

            return ans;
        }

        public static string GenerateOTP(string sec32, int Tint, int digit, string algorithm)
        {
            foreach (char a in sec32)
            {
                if (Char.IsUpper(a))
                {
                    string b32 = FromBase32(sec32);
                    sec32 = str2hex(b32).ToLower();
                    break;
                }
            }

            int seconds = Tint;
            long T0 = 0; // default=0   ->  T를 unix 시간으로 구했으니 이대로 0
            if (Tint< 27000000)
            {
                //user set Tint as timestep
                long X = Convert.ToInt64(seconds);
                long curMs = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                long current = curMs / 1000L;   // ms 에서 s로
                long Tlong = (current - T0) / X;
                Tint = (int)Tlong;

            }
            long T = Convert.ToInt64(Tint);

            string result = "";

            string cntr = string.Format("{0:X}", T).ToUpper();
            while (cntr.Length < 16) cntr = "0" + cntr;

            byte[] sec = hexStr2Bytes(sec32);
            byte[] msg = hexStr2Bytes(cntr);

            byte[] hash = hmac_sha(algorithm, sec, msg);

            int offset = hash[hash.Length - 1] & 0xf;
            int binary =
                ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);
            int otp = binary % DIGITS_POWER[digit];

            result = Convert.ToString(otp);
            while (result.Length < digit)
            {
                result = "0" + result;
            }

            return result;
        }

        private static string FromBase32(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                throw new ArgumentNullException("input");
            }

            input = input.TrimEnd('='); //remove padding characters
            int byteCount = input.Length * 5 / 8; //this must be TRUNCATED
            byte[] returnArray = new byte[byteCount];

            byte curByte = 0, bitsRemaining = 8;
            int mask = 0, arrayIndex = 0;

            foreach (char c in input)
            {
                int cValue = CharToValue(c);

                if (bitsRemaining > 5)
                {
                    mask = cValue << (bitsRemaining - 5);
                    curByte = (byte)(curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = cValue >> (5 - bitsRemaining);
                    curByte = (byte)(curByte | mask);
                    returnArray[arrayIndex++] = curByte;
                    curByte = (byte)(cValue << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            //if we didn't end with a full byte
            if (arrayIndex != byteCount)
            {
                returnArray[arrayIndex] = curByte;
            }

            return Encoding.Default.GetString(returnArray);
        }

        private static int CharToValue(char c)
        {
            int value = (int)c;

            //65-90 == uppercase letters
            if (value < 91 && value > 64)
            {
                return value - 65;
            }
            //50-55 == numbers 2-7
            if (value < 56 && value > 49)
            {
                return value - 24;
            }
            //97-122 == lowercase letters
            if (value < 123 && value > 96)
            {
                return value - 97;
            }

            throw new ArgumentException("Character is not a Base32 character.", "c");
        }

        private static char ValueToChar(byte b)
        {
            if (b < 26)
            {
                return (char)(b + 65);
            }

            if (b < 32)
            {
                return (char)(b + 24);
            }

            throw new ArgumentException("Byte is not a value Base32 value.", "b");
        }

        private static byte[] hexStr2Bytes(string hex)
        {
            byte[] convert = new byte[hex.Length / 2];

            int length = convert.Length;
            for (int i = 0; i < length; i++)
            {
                convert[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return convert;
        }

        private static string str2hex(string strData)
        {
            string resultHex = string.Empty;
            byte[] arr_byteStr = Encoding.Default.GetBytes(strData);

            foreach (byte byteStr in arr_byteStr)
            {
                resultHex += string.Format("{0:X2}", byteStr);
            }

            return resultHex;
        }

        private static byte[] hmac_sha(string crypto, byte[] keyBytes, byte[] text)
        {
            byte[] enc = null;

            if (crypto.Length > 3)
            {
                crypto = crypto.ToLower();
                crypto = crypto.Split('a')[1];
            }
            if (crypto.StartsWith("1"))
            {
                /*HMACSHA1 sha1 = new HMACSHA1(keyBytes);
                enc = sha1.ComputeHash(text);*/
                using (HMACSHA1 sha1 = new HMACSHA1(keyBytes))
                {
                    enc = sha1.ComputeHash(text);
                }
            }
            else if (crypto.StartsWith("2"))
            {
                /*HMACSHA256 sha2 = new HMACSHA256(keyBytes);
                enc = sha2.ComputeHash(text);*/
                using (HMACSHA256 sha2 = new HMACSHA256(keyBytes))
                {
                    enc = sha2.ComputeHash(text);
                }
            }
            else if (crypto.StartsWith("5"))
            {
                /*HMACSHA512 sha5 = new HMACSHA512(keyBytes);
                enc = sha5.ComputeHash(text);*/
                using (HMACSHA512 sha5 = new HMACSHA512(keyBytes))
                {
                    enc = sha5.ComputeHash(text);
                }
            }
            return enc;
        }

        private static int[] DIGITS_POWER
        // 0 1  2   3    4     5      6       7        8
        = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    }
}

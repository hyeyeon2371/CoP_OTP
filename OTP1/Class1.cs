using System;
using System.Security.Cryptography;
using System.Linq;

// Hyeyeon Park 
namespace OTP1
{
    public class TOTP
    {
        public static String GenerateOTP(String secretKey, int seconds, int digit, String algorithm)
        {
            DateTime startTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            long counter = (long)Math.Floor((DateTime.UtcNow - startTime).TotalSeconds / seconds);


            byte[] message = BitConverter.GetBytes(counter);
            Array.Reverse(message);
            byte[] secret = System.Text.Encoding.UTF8.GetBytes(secretKey);
            byte[] hash;


            switch (algorithm)
            {
                case "SHA1":
                    using (HMACSHA1 hmac = new HMACSHA1(secret, true))
                    {
                        hash = hmac.ComputeHash(message);
                    }
                    break;

                case "SHA256":
                default:
                    using (HMACSHA256 hmac = new HMACSHA256(secret))
                    {
                        hash = hmac.ComputeHash(message);
                    }
                    break;
         
            }

            int binaryCode = GetBinayCode(hash);
            int otp = Convert.ToInt32(binaryCode % Math.Pow(10, digit));

            string otpStr;
            if (digit == 6)
            {
                otpStr = otp.ToString("D6");
            }
            else
            {
                otpStr = otp.ToString("D8");
            }


            Console.WriteLine(otpStr);

            var n1 = otpStr.Substring(0, digit / 2);
            var n2 = otpStr.Substring(digit / 2, digit/2);
            return n1 + " " + n2;
        }

        private static int GetBinayCode(byte[] hash)
        {
            int offset = hash[hash.Length - 1] & 0xf;
            int binaryCode = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);
            return binaryCode;
        }

        static int idx = 0;
        static String[] prevOtp = new String[3];
        public static Boolean VerifyOTP(String otp, String secretKey, int seconds, int digit, String algorithm)
        {
            // Log
            Console.WriteLine("1) Start Verify");
            printOtpLog();


            // 이미 사용된 번호 검증 
            foreach (var item in prevOtp)
            {
                if (item != null && item.Equals(otp))
                {
                    return false;
                }
            }

            // 검증된 번호는 Array에 보관 
            String currentOtp = GenerateOTP(secretKey, seconds, digit, algorithm);
            if (otp.Equals(currentOtp.Replace(" ", "")))
            {
                if(idx == prevOtp.Length)
                {
                    idx = 0;
                }

                prevOtp[idx++] = otp;
               
                // Log
                Console.WriteLine("2) End Verify");
                printOtpLog();

                return true;
            }

            return false;
        }

        private static void printOtpLog()
        {
           var  msg = "";
            foreach (var item in prevOtp)
            {
                if (item == null)
                {
                    msg += "EMPTY  ";
                }
                else
                {
                    msg += item + "  ";
                }

            }
            Console.WriteLine(msg);
        }
    }
}

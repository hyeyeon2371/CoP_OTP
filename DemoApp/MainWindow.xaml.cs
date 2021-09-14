using System;
using System.Windows;

namespace DemoApp
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        private String SECRET_KEY = "otp";
        private String ALGORITHM = "SHA256";
        private int TIME = 60;
        private int DIGIT = 6;
   

        public MainWindow()
        {
            InitializeComponent();
        }

        // 인증 버튼 클릭 
        private void Auth_Button_Click(object sender, RoutedEventArgs e)
        {
            // 입력한 OTP 번호 
            String inputOtp = inputOtpText.Text;
            Boolean isSuccess = VerifyOTP1(inputOtp);


            if (isSuccess)
            {
                MessageBox.Show("Success");
            } else
            {
                MessageBox.Show("Failed");
            }
            
        }

        // 번호 생성 버튼 클릭 
        private void Generate_Buton_Click(object sender, RoutedEventArgs e)
        {
            String otp = GenerateOTP1();
            NewOtpText.Text = otp;
        }

        // OTP1 호출 
        private Boolean VerifyOTP1(String otp)
        {
            return OTP1.TOTP.VerifyOTP(otp, SECRET_KEY, TIME, DIGIT, ALGORITHM);
        }

        private String GenerateOTP1()
        {
            return OTP1.TOTP.GenerateOTP(SECRET_KEY, TIME, DIGIT, ALGORITHM);
        }
    }
}

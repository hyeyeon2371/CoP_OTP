using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace DemoApp
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // 인증 버튼 클릭 
        private void Auth_Button_Click(object sender, RoutedEventArgs e)
        {
            Boolean isSuccess = false;
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
            String otp = "9999 9999";
            NewOtpText.Text = otp;
        }
    }
}

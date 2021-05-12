using IdentityModel.OidcClient;
using IdentityModel.OidcClient.Browser;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
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

namespace AuthenticationWithWPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private OidcClient _oidcClient = null;
        public MainWindow()
        {
            InitializeComponent();
        }

        private LoginResult result;

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            var options = new OidcClientOptions()
            {
                Authority = "https://localhost:5000",
                ClientId = "WpfApp",
                PostLogoutRedirectUri = "https://localhost/signout-wpf-app-oidc",
                Scope = "openid profile api.WebApp",
                RedirectUri = "https://localhost/sigin-wpf-app-oidc",
                ClientSecret= "secret",
                ResponseMode=OidcClientOptions.AuthorizeResponseMode.Redirect,
                Flow=OidcClientOptions.AuthenticationFlow.AuthorizationCode,
                Browser = new WpfEmbeddedBrowser()
            };

            _oidcClient = new OidcClient(options);

           
            try
            {
                result = await _oidcClient.LoginAsync();
            }
            catch (Exception ex)
            {
               // Message.Text = $"Unexpected Error: {ex.Message}";
                return;
            }

            if (result.IsError)
            {
               // Message.Text = result.Error == "UserCancel" ? "The sign-in window was closed before authorization was completed." : result.Error;
            }
            else
            {
                var name = result.User.Identity.Name;

                if (!String.IsNullOrEmpty(name))
                {
                    tbUserName.Visibility = Visibility.Visible;
                    tbUserName.Text = name;

                    btnLogout.Visibility = Visibility.Visible;
                    btnLogin.Visibility = Visibility.Hidden;

                    btnCallApi.Visibility = Visibility.Visible;
                }


                

               // Message.Text = $"Hello {name}";
            }
        }

        private async void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var logoutRequest = new LogoutRequest
            {
                IdTokenHint = result.IdentityToken,
                BrowserDisplayMode = DisplayMode.Visible
            };

            var resultLogOut = await _oidcClient.LogoutAsync(logoutRequest);
            if (!resultLogOut.IsError)
            {
                btnLogin.Visibility = Visibility.Visible;
                btnLogout.Visibility = Visibility.Hidden;

                tbUserName.Text = null;
                tbUserName.Visibility = Visibility.Hidden;
                btnCallApi.Visibility = Visibility.Hidden;
                return;
            }

            return;
        }

        private async void btnCallApi_Click(object sender, RoutedEventArgs e)
        {

            var client = new HttpClient();

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

            client.BaseAddress = new Uri("https://localhost:5000");


            var CallApiresult = await client.GetAsync("/api/user");  // https://localhost:5000/api/user

            var items= await CallApiresult.Content.ReadAsStringAsync();

            lst.ItemsSource = (List<UserVm>)JsonConvert.DeserializeObject(items, typeof(List<UserVm>));


        }
    }
}

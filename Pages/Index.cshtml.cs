using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using EncryptionWeb.Models;
using EncryptionWeb.Services;

namespace EncryptionWeb.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty]
        public string Text { get; set; }

        [BindProperty]
        public string Algorithm { get; set; } = "AES";

        public EncryptionResult Result { get; set; }
        public string Error { get; set; }

        public void OnGet()
        {
        }

        public void OnPost()
        {
            if (string.IsNullOrEmpty(Text))
            {
                Error = "Введите текст.";
                return;
            }

            EncryptionService service = new EncryptionService();

            if (Algorithm == "AES")
            {
                Result = service.EncryptAes(Text);
            }
            else if (Algorithm == "RSA")
            {
                if (Encoding.UTF8.GetByteCount(Text) > 190)
                {
                    Error = "Для RSA текст должен занимать не более 190 байт UTF-8. Сократите текст или выберите AES.";
                    return;
                }
                Result = service.EncryptRsa(Text);
            }
            else
            {
                Error = "Выберите AES или RSA.";
            }
        }
    }
}

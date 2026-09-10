using NetchX.Properties;
using NetchX.Utils;

namespace NetchX.Forms;

[Fody.ConfigureAwait(true)]
public partial class AboutForm : Form
{
    public AboutForm()
    {
        InitializeComponent();
        Icon = Resources.icon;
    }

    private void AboutForm_Load(object sender, EventArgs e)
    {
        i18N.TranslateForm(this);
    }

    private void NetchXPictureBox_Click(object sender, EventArgs e)
    {
        Utils.Utils.Open("https://github.com/NetchX/NetchX");
    }

    private void RepositoryLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        Utils.Utils.Open("https://github.com/pwnless/NetchX");
    }

    private void SponsorPictureBox_Click(object sender, EventArgs e)
    {
        Utils.Utils.Open("https://www.mansora.co");
    }
}

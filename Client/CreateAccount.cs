using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.Sockets;

namespace SimpleAsyncServerV2Security
{
    public partial class CreateAccount : Form
    {

        public bool ServerDead;
        public bool AccountCreated;
        EncryptionAES encryptionAES = new();
        ClientData _Client;
        Socket _ServerSocket;
        private byte[] _buffer = new byte[1024];

        public CreateAccount(Socket ServerSocket, ClientData client)
        {
            InitializeComponent();
            _ServerSocket = ServerSocket;
            _Client = client;
            _ServerSocket.SendTimeout = 2000;
            _ServerSocket.ReceiveTimeout = 2000;

        }

        private void BtnCreateAccount_Click(object sender, EventArgs e)
        {
            string AllowedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!?_";

            if (TxtBoxUserName.Text != "" && TxtBoxPassword.Text != "" && TxtBoxConfirmPass.Text != "")
            {
                if (TxtBoxUserName.Text.Length <= 16)
                {
                    if (TxtBoxPassword.Text.Length <= 256 && TxtBoxPassword.Text.Length >=4)
                    {
                        if (TxtBoxUserName.Text.All(c => AllowedCharacters.Contains(c)))
                        {
                            if (TxtBoxPassword.Text == TxtBoxConfirmPass.Text)
                            {
                                if (AccountIsAllowed(TxtBoxUserName.Text, TxtBoxPassword.Text))
                                {
                                    AccountCreated = true;
                                    MessageBox.Show("Account has been created", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                                    this.Close();
                                }
                                else
                                ClearAllBoxes();
                            }
                            else
                                MessageBox.Show("Passwords don't match.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            ClearPasswordBoxes();
                        }
                        else
                            MessageBox.Show("Only letters and numbers and !?_ are allowed in username", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        ClearPasswordBoxes();
                    }
                    else
                        MessageBox.Show("Max password length is 256 characters. Min password length is 4 charaters", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    ClearPasswordBoxes();
                }
                else
                    MessageBox.Show("Max username length is 16 characters.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                ClearAllBoxes();
            }
            else
                MessageBox.Show("Please enter a username and password.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        

        private bool AccountIsAllowed(string userName, string password)
        {
            try
            {
                DataSerializer DD = new(userName, password, "");

                byte[] EncryptedMessageOut = encryptionAES.EncryptDataBufferAES(DD.AccountPacketToByteArray(), _Client);
                _ServerSocket.Send(EncryptedMessageOut, 0, EncryptedMessageOut.Length, SocketFlags.None);


                int recievedAes = _ServerSocket.Receive(_buffer);
                Array.Resize(ref _buffer, recievedAes);
                byte[] decryptedBuffer = encryptionAES.DecryptDataBufferAES(_buffer, _Client);

                DataSerializer DD2 = new(decryptedBuffer);
                if (DD2.Message == "True")
                {
                    _Client.Name = TxtBoxUserName.Text;
                    return true;
                }
                else
                {
                    MessageBox.Show("Account username already exists.", "Login", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
            }
            catch (SocketException ex)
            {
                ServerDead = true;
                MessageBox.Show($"Socket exception, error. Target machine not responding. Timeout.\n\nTraceback: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                this.Close();
                return false;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Login responce error.\n\nTraceback: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }


        }

        private void ClearAllBoxes()
        {
            TxtBoxUserName.Clear();
            TxtBoxPassword.Clear();
            TxtBoxConfirmPass.Clear();
        }
        private void ClearPasswordBoxes()
        {
            TxtBoxPassword.Clear();
            TxtBoxConfirmPass.Clear();
        }
        private void BtnClose_Click(object sender, EventArgs e)
        {
            // Close current form
            this.Close();
        }
        
        private void LinkLblHelp_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            MessageBox.Show($"Formatting help:\n\n-Max password length is 256 characters.\n-Min password length is 4 charaters.\n-Max username length is 16 characters.\n-Only letters and numbers and !?_ are allowed in username.\n-Please enter a username and password.", "Create account - help", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void CheckBoxShowPass_CheckedChanged(object sender, EventArgs e)
        {
            //TxtBoxPassword.PasswordChar = '*';
            if (CheckBoxShowPass.Checked)
            {
                TxtBoxPassword.UseSystemPasswordChar = false;
                TxtBoxConfirmPass.UseSystemPasswordChar = false;
            }
            else if (!CheckBoxShowPass.Checked)
            {
                TxtBoxPassword.UseSystemPasswordChar = true;
                TxtBoxConfirmPass.UseSystemPasswordChar = true;
            }
        }
    }
}

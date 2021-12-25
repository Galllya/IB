using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;

namespace ServerForm
{
    public partial class Server : Form
    {
        public Socket _serverSocket, _clientSocket;
        private const int BUFFER_SIZE = 1024; 
        private static byte[] _buffer = new byte[BUFFER_SIZE];
        private const int _port = 3215;
        public Users users = new();
        public Server()
        {
            InitializeComponent();
            StartServer();
        }

        private void StartServer()
        {
            try
            {
                _serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _serverSocket.Bind(new IPEndPoint(IPAddress.Any, _port));
                _serverSocket.Listen(2);
                _serverSocket.BeginAccept(new AsyncCallback(AcceptCallBack), null);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Server start error: {ex.Message}", "Server", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AcceptCallBack(IAsyncResult AR)
        {
            
            _clientSocket = _serverSocket.EndAccept(AR); 
            _clientSocket.SendBufferSize = BUFFER_SIZE;
            _clientSocket.ReceiveBufferSize = BUFFER_SIZE; 

            User client = new(_clientSocket);
            users.AddUser(client);

            AppendToTextBoxServer($"{_clientSocket.RemoteEndPoint} has connected.");

]            _clientSocket.BeginReceive(_buffer, 0, _buffer.Length, SocketFlags.None, new AsyncCallback(RecieveCallBack), _clientSocket);
            _serverSocket.BeginAccept(new AsyncCallback(AcceptCallBack), null);
            
        }



   
        
        private void RecieveCallBack(IAsyncResult AR)
        {
            try
            {
                Socket _clientSocket = (Socket)AR.AsyncState;
                int recieved = _clientSocket.EndReceive(AR);



                if (recieved == 0)
                {
                    if (users.GetUserName(_clientSocket) == null)
                    {
                        AppendToTextBoxServer($"{_clientSocket.RemoteEndPoint} disconnected.");
                        DisconnectClient(_clientSocket);
                        return;
                    }
               
                    SendToAllClients(users.GetUserName(_clientSocket), "has disconnected.");
                    AppendToTextBoxServer($"{_clientSocket.RemoteEndPoint} disconnected.");
                    DisconnectClient(_clientSocket);
                    return;
                }

                User currentUser = users.GetUser(_clientSocket);

                if (currentUser.RsaPrivateServerKey != null && currentUser.AesPrivateKey != null)
                {

                    byte[] encryptedDatabuf = new byte[recieved];
                    Array.Copy(_buffer, encryptedDatabuf, recieved);
          
                    byte[] databuf = DecryptDataBuffer(encryptedDatabuf, currentUser);
             
                    DataSerializerServer DD = new(databuf);
                    if (DD.AccountSetBool)
                    {
                        AccountManagement AM = new();
                        if (!AM.AccountNameExists(DD.Name))
                        {
                            if (AM.AccountCreateUser(DD.Name, DD.Password))
                                users.EditUserName(_clientSocket, DD.Name);
                            DataSerializerServer DSS = new(DD.Name, "", "True");
                            byte[] AccountPacket = DSS.AccountPacketToByteArray();
                            byte[] EncryptedAccountPacket = EncryptWithAES(AccountPacket, currentUser);

                            AppendToTextBoxServer($"{_clientSocket.RemoteEndPoint} assigned name - {DD.Name}");
                            _clientSocket.BeginSend(EncryptedAccountPacket, 0, EncryptedAccountPacket.Length, SocketFlags.None, new AsyncCallback(SendCallBack), _clientSocket);

                            SendToAllClients(DD.Name, "has connected.");
                            
                        }
                        else
                        {
                            DataSerializerServer DSS = new(DD.Name, "", "False");
                            byte[] AccountPacket = DSS.AccountPacketToByteArray();
                            byte[] EncryptedAccountPacket = EncryptWithAES(AccountPacket, currentUser);
                            _clientSocket.BeginSend(EncryptedAccountPacket, 0, EncryptedAccountPacket.Length, SocketFlags.None, new AsyncCallback(SendCallBack), _clientSocket);
                        }
                    }
                    else if (DD.LoginGetBool)
                    {

                        AccountManagement AM = new();
                 
                        if (AM.CheckLogin(DD.Name, DD.Password))
                        {
                            if (users.UserLoggedIn(DD.Name))
                            {
                                DataSerializerServer DSS = new(DD.Name, "", "Login");

                                AppendToTextBoxServer($"{_clientSocket.RemoteEndPoint} attempted double login: {DD.Name}");

                                byte[] LoginPacket = DSS.LoginPacketToByteArray();

                                byte[] EncryptedLoginPacket = EncryptWithAES(LoginPacket, currentUser);

                                _clientSocket.BeginSend(EncryptedLoginPacket, 0, EncryptedLoginPacket.Length, SocketFlags.None, new AsyncCallback(SendCallBack), _clientSocket);
                            }
                            else
                            {
                                users.EditUserName(_clientSocket, DD.Name);
                                DataSerializerServer DSS = new(DD.Name, "", "True");

                                AppendToTextBoxServer($"{_clientSocket.RemoteEndPoint} assigned name - {DD.Name}");

                                byte[] LoginPacket = DSS.LoginPacketToByteArray();

                                byte[] EncryptedLoginPacket = EncryptWithAES(LoginPacket, currentUser);

                                _clientSocket.BeginSend(EncryptedLoginPacket, 0, EncryptedLoginPacket.Length, SocketFlags.None, new AsyncCallback(SendCallBack), _clientSocket);

                                SendToAllClients(DD.Name, "has connected.");
                            }
                        }
                        else
                        {
                            DataSerializerServer DSS = new(DD.Name, "", "False");
                            byte[] LoginPacket = DSS.LoginPacketToByteArray();
                            byte[] EncryptedLoginPacket = EncryptWithAES(LoginPacket, currentUser);

                            _clientSocket.BeginSend(EncryptedLoginPacket, 0, EncryptedLoginPacket.Length, SocketFlags.None, new AsyncCallback(SendCallBack), _clientSocket);

                        }
                    }
                    else
                    {
                   
                        SendToAllClients(currentUser.Name, DD.Message);
                    }

                }
                else
                {
              
                    byte[] databuf = new byte[recieved];
                    Array.Copy(_buffer, databuf, recieved);

                    DataSerializerServer DD = new(databuf);
                    if (DD.RSAPublicKeyBool)
                    {
                 
                        RSA ServerRSA = RSA.Create();
                        users.AddRSAPrivate(_clientSocket, ServerRSA);

                        users.AddRSAPublic(_clientSocket, DD.RSAPrivateMod, DD.RSAPrivateExp);
                        using (Aes aes = Aes.Create())
                        {
                            users.AddAESPrivate(_clientSocket, aes.Key, aes.IV);
                         
                            byte[] EncyptedMessage = RSAEncryptKey(users.GetUser(_clientSocket), aes);

                            _clientSocket.BeginSend(EncyptedMessage, 0, EncyptedMessage.Length, SocketFlags.None, new AsyncCallback(SendCallBack), _clientSocket);
                        }
                    
                    }
                }
                _clientSocket.BeginReceive(_buffer, 0, _buffer.Length, SocketFlags.None, new AsyncCallback(RecieveCallBack), _clientSocket);
            }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                MessageBox.Show($"RecieveCallBack Error\n\nTraceBack: {ex.Message}", "Server", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }







        private void SendCallBack(IAsyncResult AR)
        {
            _clientSocket = (Socket)AR.AsyncState;
            _clientSocket.EndSend(AR);
        }

        private void SendToAllClients(string name, string message)
        {
   
            DataSerializerServer DD = new(name, message);
            AppendToTextBox($"{name}: {message}");
            foreach(User user in users.UsersWithEncryption())
            {
                try
                {
                    byte[] encryptedMessage = EncryptWithAES(DD.MessageToByteArray(), user);
                    user.ClientSocket.BeginSend(encryptedMessage, 0, encryptedMessage.Length, SocketFlags.None, new AsyncCallback(SendCallBack), user.ClientSocket);
                }
                catch (Exception ex)
                {
                    AppendToTextBoxServer($"SendToAllClients User: {user.Name} error: {ex.Message}");
                }
            }
        }

        private void DisconnectClient(Socket client)
        {
            // TODO
            try
            {
                MethodInvoker invoker = new(delegate
                {
                    // Remove client entry and close client 
                    users.RemoveUserBySocket(client);
                    client.Close();
                });
                this.Invoke(invoker);
            }
            catch(Exception ex)
            {
                MessageBox.Show($"ServerShutdown error: {ex.Message}", "Server", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            
        }
        private void DisconnectAllClients()
        {
            
            try
            {
                MethodInvoker invoker = new(delegate
                {
                    foreach (Socket s in users.GetSockets())
                    {
                        s.Close();
                    }
                    users.RemoveAllUsers();
                });
            }
            catch (Exception)
            {
                AppendToTextBoxServer($"Error DisconnectAllClients method.");
            }
            // TODO
        }

        // Cryptography methods
        #region RSA
        // Encrypt AES Key with "RSA"!!!!!!!!!!!!!!
        private byte[] RSAEncryptKey(User user, Aes aes)
        {
            DataSerializerServer DD = new(aes.Key, aes.IV);
            RSA TempRsa = RSA.Create();
            RSAParameters TempRsaInfo = TempRsa.ExportParameters(false);

            // Import public key info rsa
            TempRsaInfo.Modulus = user.RsaPublicMod;
            TempRsaInfo.Exponent = user.RsaPublicExp;
            TempRsa.ImportParameters(TempRsaInfo);
            // \RSA
            // Turn message to format and encrypt
            byte[] EncryptedMessage = TempRsa.Encrypt(DD.AESToBytesArray(), RSAEncryptionPadding.Pkcs1);
            
            // Ready to send
            return EncryptedMessage;
        }
        #endregion RSA
        #region AES
        private byte[] EncryptWithAES(byte[] UnencryptedMessage, User CurrentUser)
        {
            byte[] key = CurrentUser.AesPrivateKey;
            byte[] IV = CurrentUser.AesPrivateIV;
            //Argument checker
            if (UnencryptedMessage == null || UnencryptedMessage.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesEnc = Aes.Create())
            {
                // Import values to aes decryptor
                aesEnc.Key = key;
                aesEnc.IV = IV;
                aesEnc.Padding = PaddingMode.Zeros;
                // Create decryptor to perform the stream transformation;
                ICryptoTransform decryptor = aesEnc.CreateDecryptor(aesEnc.Key, aesEnc.IV);

                // Create streams for decryption
                // LOOK INTO THIS
                using (var encryptor = aesEnc.CreateEncryptor(aesEnc.Key, aesEnc.IV))
                {
                    return PerformCryptogrphy(UnencryptedMessage, encryptor);
                }
            }
        }


        private byte[] DecryptDataBuffer(byte[] EncryptedBuffer, User CurrentUser)
        {
            byte[] key = CurrentUser.AesPrivateKey;
            byte[] IV = CurrentUser.AesPrivateIV;
            //Argument checker
            if (EncryptedBuffer == null || EncryptedBuffer.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Create a new AES object and import key and IV
            // AES DECRYPTOR

            using (Aes aesDec = Aes.Create())
            {
                // Import values to aes decryptor
                aesDec.Key = key;
                aesDec.IV = IV;
                aesDec.Padding = PaddingMode.Zeros;
                // Create streams for decryption
                // LOOK INTO THIS
                // Create decryptor to perform the stream transformation;
                // ICryptoTransform decryptor = aesDec.CreateDecryptor(aesDec.Key, aesDec.IV);

                using (var Decryptor = aesDec.CreateDecryptor(aesDec.Key, aesDec.IV))
                {
                    return PerformCryptogrphy(EncryptedBuffer, Decryptor);
                }
            }
        }
        // Can return encryped and decrypted (LOOKINTO THIS WHEN YOU CAN) THIS WAS KINDA A CTRLC CTRLV (NOT PROUD)
        public byte[] PerformCryptogrphy(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {

                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
        #endregion AES


        private void AppendToTextBox(string message)
        {
            MethodInvoker invoker = new(delegate
            {
                // Check difference with \r
                RichTxtBoxMain.Text += ($"\r\n {message}");
            });
            this.Invoke(invoker);
        }
        private void AppendToTextBoxServer(string message)
        {
            MethodInvoker invoker = new(delegate
            {
                // Check difference with \r
                RichTxtBoxServer.Text += ($"\r\n {message}");
            });
            this.Invoke(invoker);
        }

        // These are server commands not for sending to clients
        private void BtnSend_Click(object sender, EventArgs e)
        {
            string ServerCommand = TxtBoxMain.Text;
            try
            {
                if (ServerCommand[0..4].ToLower() == "list")
                {
                    AppendToTextBoxServer($"Number of users connected: {users.UserDataList.Count}");
                    foreach (User user in users.UserDataList)
                    {
                        var name = user.Name;
                        if (name != null)
                        {
                            AppendToTextBoxServer($"{user.ClientSocket.RemoteEndPoint} >>> {name}");
                        }
                        else
                        {
                            AppendToTextBoxServer($"{user.ClientSocket.RemoteEndPoint} >>> [NAME_NOT_SET]");
                        }
                    }
                    // Print number of connected clients and list each ones socket (IP:PORT) and name
                }
                else if (ServerCommand[0..4].ToLower() == "help")
                {
                    AppendToTextBoxServer($"Server commands:\n\nkick [Username] (Kicks given user)\nList (Shows all connected users)\nSay [Message] (Say somthing as the server)\nhelp (re-show this message)\n");
                }
                else if (ServerCommand[0..5].ToLower() == "kick ")
                {
                    var userSocket = users.GetSocketWithUserName(ServerCommand[5..]);
                    if (userSocket != null)
                    {
                        DisconnectClient(userSocket);
                        SendToAllClients(ServerCommand[5..], "has disconnected.");
                    }
                    else
                    {
                        // Client not found
                        AppendToTextBoxServer($"'{ServerCommand[5..]}' not found.");
                    }
                }
                // If empty do nothing
                
                else if (ServerCommand[0..4].ToLower() == "say ")
                {
                    string message = ServerCommand[4..];
                    SendToAllClients("[SERVER]", message);
                }
                else
                {
                    AppendToTextBoxServer($"Command not recognised: '{ServerCommand}'");
                }
                TxtBoxMain.Clear();
            }
            catch (ArgumentOutOfRangeException)
            {
                if (ServerCommand != "")
                {
                    AppendToTextBoxServer($"Command not recognised: '{ServerCommand}'");
                    TxtBoxMain.Clear();
                }
                
            }
            


        }

        private void RichTxtBoxMain_TextChanged(object sender, EventArgs e)
        {
            // set the current caret position to the end
            RichTxtBoxMain.SelectionStart = RichTxtBoxMain.Text.Length;
            // scroll it automatically
            RichTxtBoxMain.ScrollToCaret();
        }

        private void RichTxtBoxServer_TextChanged(object sender, EventArgs e)
        {
            // set the current caret position to the end
            RichTxtBoxServer.SelectionStart = RichTxtBoxServer.Text.Length;
            // scroll it automatically
            RichTxtBoxServer.ScrollToCaret();
        }



        private void CheckKeyPressedMsg(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == 13) //Enter ASCII Key Char
            {
                e.Handled = true; //Disable "dong" warning noise
                BtnSend_Click(sender, e); //Call send method
            }
        }

        private void BtnClose_Click(object sender, EventArgs e)
        {
            DisconnectAllClients();
            //_serverSocket.Shutdown(SocketShutdown.Both);
            Application.Exit();
        }
    }
}
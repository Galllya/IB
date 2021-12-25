using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace ServerForm
{
    class DataSerializerServer
    {


        public bool RSAPublicKeyBool { get; set; }
        public bool AESPrivateKeyBool { get; set; }
        public bool AccountSetBool { get; set; }
        public bool LoginGetBool { get; set; }

        public RSAParameters RSAParameter { get; set; }

        public byte[] RSAPrivateMod { get; set; } 
        public byte[] RSAPrivateExp { get; set; }
        
        
        public byte[] AESPrivateKey { get; set; }
        public byte[] AESPrivateIV { get; set; }


        public string Name { get; set; }
        public string Password { get; set; }
        public string Message { get; set; }

        public DataSerializerServer(RSAParameters rsaParameters)
        {
            RSAParameter = rsaParameters;
        }

        public DataSerializerServer(byte[] aesPrivateKey, byte[] aesPrivateIV)
        {
            AESPrivateKey = aesPrivateKey;
            AESPrivateIV = aesPrivateIV;
        }

        public DataSerializerServer(string name, string password, string message)
        {
            Name = name;
            Password = password;
            Message = message;
        }




        public DataSerializerServer(string name, string message)
        {
            Name = name;
            Message = message;
        }

        public DataSerializerServer(byte[] data)
        {
            RSAPublicKeyBool = BitConverter.ToBoolean(data, 0);
            AESPrivateKeyBool = BitConverter.ToBoolean(data, 1);
            AccountSetBool = BitConverter.ToBoolean(data, 2);
            LoginGetBool = BitConverter.ToBoolean(data, 3);

            if (RSAPublicKeyBool)
            {
                int modLength = BitConverter.ToInt32(data, 4); //4 bytes
                RSAPrivateMod = data[8..(8 + modLength)];

                int expLength = BitConverter.ToInt32(data, 8 + modLength); // 4bytes
                RSAPrivateExp = data[(12 + modLength)..(12 + modLength + expLength)]; 
            }
            else if (AESPrivateKeyBool)
            {
                int keyLength = BitConverter.ToInt32(data, 4);
                AESPrivateKey = data[8..(8 + keyLength)];

                int IVLength = BitConverter.ToInt32(data, 8 + keyLength);
                AESPrivateIV = data[(12 + keyLength)..(12 + keyLength + IVLength)];
            }
            else if (AccountSetBool || LoginGetBool) 
            {
                int nameLength = BitConverter.ToInt32(data, 4);
                Name = Encoding.ASCII.GetString(data, 8, nameLength);

                int passwordLength = BitConverter.ToInt32(data, nameLength + 8);
                Password = Encoding.ASCII.GetString(data, 12 + nameLength, passwordLength);


                int messageLength = BitConverter.ToInt32(data, nameLength + passwordLength + 12);
                Message = Encoding.ASCII.GetString(data, 16 + nameLength + passwordLength, messageLength);
            }
            else
            {
                int nameLength = BitConverter.ToInt32(data, 4);
                Name = Encoding.ASCII.GetString(data, 8, nameLength);

                int messageLength = BitConverter.ToInt32(data, 8 + nameLength);
                Message = Encoding.ASCII.GetString(data, nameLength + 12, messageLength);
            }
        }
        public byte[] RSAToByteArray()
        {
            List<byte> byteList = new();

            byte[] mod = RSAParameter.Modulus;
            byte[] exp = RSAParameter.Exponent;

            byte[] set = { 0x01, 0x00, 0x00, 0x00 };
            byteList.AddRange(set);


            byteList.AddRange(BitConverter.GetBytes(mod.Length));
            byteList.AddRange(mod); 

            byteList.AddRange(BitConverter.GetBytes(exp.Length));
            byteList.AddRange(exp);

            return byteList.ToArray();
        }
        public byte[] AESToBytesArray()
        {
            List<byte> byteList = new();
            byte[] set = { 0x00, 0x01, 0x00, 0x00 };
            byteList.AddRange(set);

            byteList.AddRange(BitConverter.GetBytes(AESPrivateKey.Length));
            byteList.AddRange(AESPrivateKey);

            byteList.AddRange(BitConverter.GetBytes(AESPrivateIV.Length));
            byteList.AddRange(AESPrivateIV);

            return byteList.ToArray();
        }
        public byte[] AccountPacketToByteArray()
        {
            List<byte> byteList = new();

            byte[] set = { 0x00, 0x00, 0x01, 0x00 };
            byteList.AddRange(set);

            byteList.AddRange(BitConverter.GetBytes(Name.Length)); 
            byteList.AddRange(Encoding.ASCII.GetBytes(Name));

            byteList.AddRange(BitConverter.GetBytes(Password.Length)); 
            byteList.AddRange(Encoding.ASCII.GetBytes(Password)); 

            byteList.AddRange(BitConverter.GetBytes(Message.Length));
            byteList.AddRange(Encoding.ASCII.GetBytes(Message));

            return byteList.ToArray();
        }

        public byte[] LoginPacketToByteArray()
        {
            List<byte> byteList = new();

            byte[] set = { 0x00, 0x00, 0x00, 0x01 };
            byteList.AddRange(set);

            byteList.AddRange(BitConverter.GetBytes(Name.Length)); 
            byteList.AddRange(Encoding.ASCII.GetBytes(Name));

            byteList.AddRange(BitConverter.GetBytes(Password.Length)); 
            byteList.AddRange(Encoding.ASCII.GetBytes(Password)); 

            byteList.AddRange(BitConverter.GetBytes(Message.Length));
            byteList.AddRange(Encoding.ASCII.GetBytes(Message));
            return byteList.ToArray();
        }

        public byte[] MessageToByteArray()
        {
            List<byte> byteList = new();

            byte[] set = { 0x00, 0x00, 0x00, 0x00 };
            byteList.AddRange(set);

            byteList.AddRange(BitConverter.GetBytes(Name.Length));
            byteList.AddRange(Encoding.ASCII.GetBytes(Name));

            byteList.AddRange(BitConverter.GetBytes(Message.Length));
            byteList.AddRange(Encoding.ASCII.GetBytes(Message));

            return byteList.ToArray();
        }
    }
}
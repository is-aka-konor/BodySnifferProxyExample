using System;

namespace BodySnifferProxy
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Trying to start the proxy!");

            var proxy = new ProxySniffer();
            proxy.SnifferStart();

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
            proxy.SnifferStop();
        }
    }
}

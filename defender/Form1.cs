using System.Diagnostics;
using System.Runtime.InteropServices;
using MinHook;

namespace Affinity
{
    public partial class Form1 : Form
    {
        [DllImport("user32.dll")]
        static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint dwAffinity);

        [DllImport("user32.dll")]
        static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        [DllImport("user32.dll")]
        static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessAffinityMask(IntPtr hProcess, out UIntPtr lpProcessAffinityMask, out UIntPtr lpSystemAffinityMask);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetProcessAffinityMask(IntPtr hProcess, UIntPtr dwProcessAffinityMask);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        static extern int GetProcessId(IntPtr handle);
        
        // Constants for window style and display affinity
        private const int GWL_STYLE = -16;
        private const int WS_MAXIMIZEBOX = 0x10000;

        // Display Affinity constants
        private const uint WDA_NONE = 0x00000000;
        private const uint WDA_MONITOR = 0x00000001;
        private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;
        
        private const int ProcessAffinityMask = 3;
        
        private UIntPtr originalAffinity;
        private int currentProcessId;
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool SetProcessAffinityMaskDelegate(IntPtr hProcess, UIntPtr dwProcessAffinityMask);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool SetWindowDisplayAffinityDelegate(IntPtr hWnd, uint dwAffinity);
        
        private SetProcessAffinityMaskDelegate originalSetProcessAffinityMask;
        private SetWindowDisplayAffinityDelegate originalSetWindowDisplayAffinity;
        
        private HookEngine hookEngine;

        private static IntPtr protectedHandle;

        public Form1()
        {
            InitializeComponent();

            Button btnTest = new Button
            {
                Text = "Test internally",
                Location = new Point(50, 50),
                Size = new Size(150, 30)
            };
            btnTest.Click += BtnTest_Click;
            Controls.Add(btnTest);
        }

        private void BtnTest_Click(object sender, EventArgs e)
        {
            TestAffinityProtection();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                bool result = SetWindowDisplayAffinity(Handle, WDA_EXCLUDEFROMCAPTURE);
                
                int style = GetWindowLong(Handle, GWL_STYLE);
                SetWindowLong(Handle, GWL_STYLE, style & ~WS_MAXIMIZEBOX);
                FormBorderStyle = FormBorderStyle.FixedSingle;
                
                currentProcessId = GetCurrentProcessId();

                // Get and store the original affinity of our process
                GetProcessAffinityMask(GetCurrentProcess(), out originalAffinity, out UIntPtr _);
                protectedHandle = Handle;
                
                InstallAffinityHooks();
                FormClosing += Form1_FormClosing;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            // Remove our API hooks when closing
            UninstallHooks();
        }

        private void InstallAffinityHooks()
        {
            try
            {
                hookEngine = new HookEngine();
                
                originalSetProcessAffinityMask = hookEngine.CreateHook("kernel32.dll", "SetProcessAffinityMask", new SetProcessAffinityMaskDelegate(SetProcessAffinityMaskHook));
                originalSetWindowDisplayAffinity = hookEngine.CreateHook("user32.dll", "SetWindowDisplayAffinity", new SetWindowDisplayAffinityDelegate(SetWindowDisplayAffinityHook));

                hookEngine.EnableHooks();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void UninstallHooks()
        {
            try
            {
                if (hookEngine != null)
                {
                    hookEngine.DisableHooks();
                    hookEngine.Dispose();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }
        
        private bool SetProcessAffinityMaskHook(IntPtr hProcess, UIntPtr dwProcessAffinityMask)
        {
            try
            {
                int processId = GetProcessId(hProcess);
                
                if (processId == currentProcessId)
                {
                    if (dwProcessAffinityMask.ToUInt64() != originalAffinity.ToUInt64())
                    {
                        Debug.WriteLine($"Blokován pokus o změnu afinity procesu {currentProcessId} pomocí SetProcessAffinityMask");
                        return true;
                    }
                }

                return originalSetProcessAffinityMask(hProcess, dwProcessAffinityMask);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Chyba v hook funkci SetProcessAffinityMask: {ex.Message}");
                return false;
            }
        }
        
        private bool SetWindowDisplayAffinityHook(IntPtr hWnd, uint dwAffinity)
        {
            try
            {
                if (hWnd == protectedHandle)
                {
                    if (dwAffinity != WDA_EXCLUDEFROMCAPTURE)
                    {
                        Debug.WriteLine($"Blocked (SetWindowDisplayAffinity) from 0x{WDA_EXCLUDEFROMCAPTURE:X} to 0x{dwAffinity:X}");
                        return true;
                    }
                }
                
                return originalSetWindowDisplayAffinity(hWnd, dwAffinity);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                return false;
            }
        }

        // Test method to verify the protection is working
        private void TestAffinityProtection()
        {
            GetProcessAffinityMask(GetCurrentProcess(), out UIntPtr currentAffinity, out UIntPtr _);
      
            UIntPtr newAffinity = new UIntPtr(1);
            bool result = SetProcessAffinityMask(GetCurrentProcess(), newAffinity);
            GetProcessAffinityMask(GetCurrentProcess(), out currentAffinity, out UIntPtr _);
            Debug.WriteLine($"Afinita po pokusu o změnu: 0x{currentAffinity.ToUInt64():X}");

            if (currentAffinity.ToUInt64() == originalAffinity.ToUInt64())
            {
                MessageBox.Show("ok", "Test", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("affinity changed", "Test", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
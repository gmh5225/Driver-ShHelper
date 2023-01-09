#ifndef _SHDRVSOCKET_H_
#define _SHDRVSOCKET_H_

/**
 * @file ShDrvSocket.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Wsk header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

#define SOCKET_ERROR            (-1)


typedef struct _SH_SOCKET_SEND {
	PSTR IPv4Address;
	PSTR Url;
	PSTR Path;
	PSTR PostData;
	PSTR ConetentLength;
	PSTR Optional;
	ULONG Port;
#define SH_SOCKET_SEND_SIZE sizeof(SH_SOCKET_SEND)
}SH_SOCKET_SEND,*PSH_SOCKET_SEND;

typedef struct _SH_SOCKET_RECV {
	PVOID ReceiveBuffer;
	ULONG ReceiveSize;
	ULONG ReceivedBytes;
#define SH_SOCKET_RECV_SIZE sizeof(SH_SOCKET_RECV)
}SH_SOCKET_RECV, *PSH_SOCKET_RECV;

/**
* @brief Socket utility
* @author Shh0ya @date 2022-12-30
*/
namespace ShSocketAPI {
	ULONG Inet_Addr(IN PSTR IPv4Address);

	NTSTATUS CreateHeader(
		IN BOOLEAN bPost,
		IN PSTR Path,
		IN PSTR Host,
		OUT PSTR Header,
		IN PSTR ContentLength = nullptr OPTIONAL);

	NTSTATUS Request(
		IN PSH_SOCKET_SEND SendData,
		OUT PSH_SOCKET_RECV RecvData,
		IN SH_REQUEST_METHOD Method);

	NTSTATUS WskStartup();

	VOID WskCleanup();

	NTSTATUS WskInitialize(
		OUT PIRP* Irp, 
		OUT PKEVENT Event);

	NTSTATUS WskBufferInitialize(
		IN PVOID Buffer,
		IN ULONG Size,
		OUT PWSK_BUF WskBuffer);

	VOID WskBufferFinalize(IN PWSK_BUF WskBuffer);

	NTSTATUS CompletionRoutine(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp,
		IN PKEVENT Event);

	PWSK_SOCKET CreateSocket(
		IN ADDRESS_FAMILY AddressFamily,
		IN USHORT SocketType,
		IN ULONG Protocol,
		IN ULONG Flags);

	NTSTATUS CloseSocket(IN PWSK_SOCKET Socket);

	NTSTATUS Connect(
		IN PWSK_SOCKET Socket, 
		IN PSOCKADDR Address);

	NTSTATUS Send(
		IN PWSK_SOCKET Socket,
		IN PVOID Buffer,
		IN ULONG Size,
		IN ULONG Flags,
		OUT PULONG SentBytes);

	NTSTATUS Recv(
		IN PWSK_SOCKET Socket,
		OUT PVOID Buffer,
		IN ULONG Size,
		IN ULONG Flags,
		OUT PULONG ReceivedBytes);

	NTSTATUS Bind(
		IN PWSK_SOCKET Socket,
		IN PSOCKADDR Address);

	NTSTATUS Accept(
		IN PWSK_SOCKET Socket,
		OUT PSOCKADDR LocalAddress OPTIONAL,
		OUT PSOCKADDR RemoteAddress OPTIONAL,
		OUT PWSK_SOCKET* AcceptedSocket);
}

#endif // !_SHDRVSOCKET_H_

namespace Octokit.Webhooks.AspNetCore;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// A read-only stream wrapper that feeds every byte read through an <see cref="IncrementalHash"/>
/// so that a running HMAC can be maintained without buffering the entire body.
/// </summary>
internal sealed class HashingStream(Stream inner, IncrementalHash hash) : Stream
{
    public override bool CanRead => inner.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new System.NotSupportedException();

    public override long Position
    {
        get => throw new System.NotSupportedException();
        set => throw new System.NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var bytesRead = inner.Read(buffer, offset, count);
        if (bytesRead > 0)
        {
            hash.AppendData(buffer, offset, bytesRead);
        }

        return bytesRead;
    }

    public override int Read(System.Span<byte> buffer)
    {
        var bytesRead = inner.Read(buffer);
        if (bytesRead > 0)
        {
            hash.AppendData(buffer[..bytesRead]);
        }

        return bytesRead;
    }

    public override async ValueTask<int> ReadAsync(System.Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var bytesRead = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (bytesRead > 0)
        {
            hash.AppendData(buffer.Span[..bytesRead]);
        }

        return bytesRead;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        this.ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush() => inner.Flush();

    public override long Seek(long offset, SeekOrigin origin) => throw new System.NotSupportedException();

    public override void SetLength(long value) => throw new System.NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new System.NotSupportedException();
}

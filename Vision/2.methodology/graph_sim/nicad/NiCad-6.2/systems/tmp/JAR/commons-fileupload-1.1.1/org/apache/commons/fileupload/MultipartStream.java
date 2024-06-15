package org.apache.commons.fileupload;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

public class MultipartStream {
  public static final byte CR = 13;
  
  public static final byte LF = 10;
  
  public static final byte DASH = 45;
  
  public static final int HEADER_PART_SIZE_MAX = 10240;
  
  protected static final int DEFAULT_BUFSIZE = 4096;
  
  protected static final byte[] HEADER_SEPARATOR = new byte[] { 13, 10, 13, 10 };
  
  protected static final byte[] FIELD_SEPARATOR = new byte[] { 13, 10 };
  
  protected static final byte[] STREAM_TERMINATOR = new byte[] { 45, 45 };
  
  protected static final byte[] BOUNDARY_PREFIX = new byte[] { 13, 10, 45, 45 };
  
  private static final int KEEP_REGION_PAD = 3;
  
  private InputStream input;
  
  private int boundaryLength;
  
  private int keepRegion;
  
  private byte[] boundary;
  
  private int bufSize;
  
  private byte[] buffer;
  
  private int head;
  
  private int tail;
  
  private String headerEncoding;
  
  public MultipartStream() {}
  
  public MultipartStream(InputStream input, byte[] boundary, int bufSize) {
    this.input = input;
    this.bufSize = bufSize;
    this.buffer = new byte[bufSize];
    this.boundary = new byte[boundary.length + BOUNDARY_PREFIX.length];
    this.boundaryLength = boundary.length + BOUNDARY_PREFIX.length;
    this.keepRegion = boundary.length + 3;
    System.arraycopy(BOUNDARY_PREFIX, 0, this.boundary, 0, BOUNDARY_PREFIX.length);
    System.arraycopy(boundary, 0, this.boundary, BOUNDARY_PREFIX.length, boundary.length);
    this.head = 0;
    this.tail = 0;
  }
  
  public MultipartStream(InputStream input, byte[] boundary) throws IOException {
    this(input, boundary, 4096);
  }
  
  public String getHeaderEncoding() {
    return this.headerEncoding;
  }
  
  public void setHeaderEncoding(String encoding) {
    this.headerEncoding = encoding;
  }
  
  public byte readByte() throws IOException {
    if (this.head == this.tail) {
      this.head = 0;
      this.tail = this.input.read(this.buffer, this.head, this.bufSize);
      if (this.tail == -1)
        throw new IOException("No more data is available"); 
    } 
    return this.buffer[this.head++];
  }
  
  public boolean readBoundary() throws MalformedStreamException {
    byte[] marker = new byte[2];
    boolean nextChunk = false;
    this.head += this.boundaryLength;
    try {
      marker[0] = readByte();
      if (marker[0] == 10)
        return true; 
      marker[1] = readByte();
      if (arrayequals(marker, STREAM_TERMINATOR, 2)) {
        nextChunk = false;
      } else if (arrayequals(marker, FIELD_SEPARATOR, 2)) {
        nextChunk = true;
      } else {
        throw new MalformedStreamException("Unexpected characters follow a boundary");
      } 
    } catch (IOException e) {
      throw new MalformedStreamException("Stream ended unexpectedly");
    } 
    return nextChunk;
  }
  
  public void setBoundary(byte[] boundary) throws IllegalBoundaryException {
    if (boundary.length != this.boundaryLength - BOUNDARY_PREFIX.length)
      throw new IllegalBoundaryException("The length of a boundary token can not be changed"); 
    System.arraycopy(boundary, 0, this.boundary, BOUNDARY_PREFIX.length, boundary.length);
  }
  
  public String readHeaders() throws MalformedStreamException {
    int i = 0;
    byte[] b = new byte[1];
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int sizeMax = 10240;
    int size = 0;
    while (i < HEADER_SEPARATOR.length) {
      try {
        b[0] = readByte();
      } catch (IOException e) {
        throw new MalformedStreamException("Stream ended unexpectedly");
      } 
      size++;
      if (b[0] == HEADER_SEPARATOR[i]) {
        i++;
      } else {
        i = 0;
      } 
      if (size <= sizeMax)
        baos.write(b[0]); 
    } 
    String headers = null;
    if (this.headerEncoding != null) {
      try {
        headers = baos.toString(this.headerEncoding);
      } catch (UnsupportedEncodingException e) {
        headers = baos.toString();
      } 
    } else {
      headers = baos.toString();
    } 
    return headers;
  }
  
  public int readBodyData(OutputStream output) throws MalformedStreamException, IOException {
    boolean done = false;
    int total = 0;
    while (!done) {
      int pad, pos = findSeparator();
      if (pos != -1) {
        output.write(this.buffer, this.head, pos - this.head);
        total += pos - this.head;
        this.head = pos;
        done = true;
        continue;
      } 
      if (this.tail - this.head > this.keepRegion) {
        pad = this.keepRegion;
      } else {
        pad = this.tail - this.head;
      } 
      output.write(this.buffer, this.head, this.tail - this.head - pad);
      total += this.tail - this.head - pad;
      System.arraycopy(this.buffer, this.tail - pad, this.buffer, 0, pad);
      this.head = 0;
      int bytesRead = this.input.read(this.buffer, pad, this.bufSize - pad);
      if (bytesRead != -1) {
        this.tail = pad + bytesRead;
        continue;
      } 
      output.write(this.buffer, 0, pad);
      output.flush();
      total += pad;
      throw new MalformedStreamException("Stream ended unexpectedly");
    } 
    output.flush();
    return total;
  }
  
  public int discardBodyData() throws MalformedStreamException, IOException {
    boolean done = false;
    int total = 0;
    while (!done) {
      int pad, pos = findSeparator();
      if (pos != -1) {
        total += pos - this.head;
        this.head = pos;
        done = true;
        continue;
      } 
      if (this.tail - this.head > this.keepRegion) {
        pad = this.keepRegion;
      } else {
        pad = this.tail - this.head;
      } 
      total += this.tail - this.head - pad;
      System.arraycopy(this.buffer, this.tail - pad, this.buffer, 0, pad);
      this.head = 0;
      int bytesRead = this.input.read(this.buffer, pad, this.bufSize - pad);
      if (bytesRead != -1) {
        this.tail = pad + bytesRead;
        continue;
      } 
      total += pad;
      throw new MalformedStreamException("Stream ended unexpectedly");
    } 
    return total;
  }
  
  public boolean skipPreamble() throws IOException {
    System.arraycopy(this.boundary, 2, this.boundary, 0, this.boundary.length - 2);
    this.boundaryLength = this.boundary.length - 2;
    try {
      discardBodyData();
      return readBoundary();
    } catch (MalformedStreamException e) {
      return false;
    } finally {
      System.arraycopy(this.boundary, 0, this.boundary, 2, this.boundary.length - 2);
      this.boundaryLength = this.boundary.length;
      this.boundary[0] = 13;
      this.boundary[1] = 10;
    } 
  }
  
  public static boolean arrayequals(byte[] a, byte[] b, int count) {
    for (int i = 0; i < count; i++) {
      if (a[i] != b[i])
        return false; 
    } 
    return true;
  }
  
  protected int findByte(byte value, int pos) {
    for (int i = pos; i < this.tail; i++) {
      if (this.buffer[i] == value)
        return i; 
    } 
    return -1;
  }
  
  protected int findSeparator() {
    int match = 0;
    int maxpos = this.tail - this.boundaryLength;
    int first = this.head;
    for (; first <= maxpos && match != this.boundaryLength; 
      first++) {
      first = findByte(this.boundary[0], first);
      if (first == -1 || first > maxpos)
        return -1; 
      for (match = 1; match < this.boundaryLength && 
        this.buffer[first + match] == this.boundary[match]; match++);
    } 
    if (match == this.boundaryLength)
      return first - 1; 
    return -1;
  }
  
  public String toString() {
    StringBuffer sbTemp = new StringBuffer();
    sbTemp.append("boundary='");
    sbTemp.append(String.valueOf(this.boundary));
    sbTemp.append("'\nbufSize=");
    sbTemp.append(this.bufSize);
    return sbTemp.toString();
  }
  
  public static class MalformedStreamException extends IOException {
    public MalformedStreamException() {}
    
    public MalformedStreamException(String message) {
      super(message);
    }
  }
  
  public static class IllegalBoundaryException extends IOException {
    public IllegalBoundaryException() {}
    
    public IllegalBoundaryException(String message) {
      super(message);
    }
  }
}

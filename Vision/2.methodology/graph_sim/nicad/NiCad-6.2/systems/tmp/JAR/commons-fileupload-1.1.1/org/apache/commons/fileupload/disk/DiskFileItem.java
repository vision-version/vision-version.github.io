package org.apache.commons.fileupload.disk;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.rmi.server.UID;
import java.util.Map;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.ParameterParser;
import org.apache.commons.io.FileCleaner;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.DeferredFileOutputStream;

public class DiskFileItem implements FileItem {
  public static final String DEFAULT_CHARSET = "ISO-8859-1";
  
  private static final String UID = (new UID()).toString().replace(':', '_').replace('-', '_');
  
  private static int counter = 0;
  
  private String fieldName;
  
  private String contentType;
  
  private boolean isFormField;
  
  private String fileName;
  
  private long size = -1L;
  
  private int sizeThreshold;
  
  private File repository;
  
  private byte[] cachedContent;
  
  private transient DeferredFileOutputStream dfos;
  
  private File dfosFile;
  
  public DiskFileItem(String fieldName, String contentType, boolean isFormField, String fileName, int sizeThreshold, File repository) {
    this.fieldName = fieldName;
    this.contentType = contentType;
    this.isFormField = isFormField;
    this.fileName = fileName;
    this.sizeThreshold = sizeThreshold;
    this.repository = repository;
  }
  
  public InputStream getInputStream() throws IOException {
    if (!isInMemory())
      return new FileInputStream(this.dfos.getFile()); 
    if (this.cachedContent == null)
      this.cachedContent = this.dfos.getData(); 
    return new ByteArrayInputStream(this.cachedContent);
  }
  
  public String getContentType() {
    return this.contentType;
  }
  
  public String getCharSet() {
    ParameterParser parser = new ParameterParser();
    parser.setLowerCaseNames(true);
    Map params = parser.parse(getContentType(), ';');
    return (String)params.get("charset");
  }
  
  public String getName() {
    return this.fileName;
  }
  
  public boolean isInMemory() {
    if (this.cachedContent != null)
      return true; 
    return this.dfos.isInMemory();
  }
  
  public long getSize() {
    if (this.size >= 0L)
      return this.size; 
    if (this.cachedContent != null)
      return this.cachedContent.length; 
    if (this.dfos.isInMemory())
      return (this.dfos.getData()).length; 
    return this.dfos.getFile().length();
  }
  
  public byte[] get() {
    if (isInMemory()) {
      if (this.cachedContent == null)
        this.cachedContent = this.dfos.getData(); 
      return this.cachedContent;
    } 
    byte[] fileData = new byte[(int)getSize()];
    FileInputStream fis = null;
    try {
      fis = new FileInputStream(this.dfos.getFile());
      fis.read(fileData);
    } catch (IOException e) {
      fileData = null;
    } finally {
      if (fis != null)
        try {
          fis.close();
        } catch (IOException e) {} 
    } 
    return fileData;
  }
  
  public String getString(String charset) throws UnsupportedEncodingException {
    return new String(get(), charset);
  }
  
  public String getString() {
    byte[] rawdata = get();
    String charset = getCharSet();
    if (charset == null)
      charset = "ISO-8859-1"; 
    try {
      return new String(rawdata, charset);
    } catch (UnsupportedEncodingException e) {
      return new String(rawdata);
    } 
  }
  
  public void write(File file) throws Exception {
    if (isInMemory()) {
      FileOutputStream fout = null;
      try {
        fout = new FileOutputStream(file);
        fout.write(get());
      } finally {
        if (fout != null)
          fout.close(); 
      } 
    } else {
      File outputFile = getStoreLocation();
      if (outputFile != null) {
        this.size = outputFile.length();
        if (!outputFile.renameTo(file)) {
          BufferedInputStream in = null;
          BufferedOutputStream out = null;
          try {
            in = new BufferedInputStream(new FileInputStream(outputFile));
            out = new BufferedOutputStream(new FileOutputStream(file));
            IOUtils.copy(in, out);
          } finally {
            if (in != null)
              try {
                in.close();
              } catch (IOException e) {} 
            if (out != null)
              try {
                out.close();
              } catch (IOException e) {} 
          } 
        } 
      } else {
        throw new FileUploadException("Cannot write uploaded file to disk!");
      } 
    } 
  }
  
  public void delete() {
    this.cachedContent = null;
    File outputFile = getStoreLocation();
    if (outputFile != null && outputFile.exists())
      outputFile.delete(); 
  }
  
  public String getFieldName() {
    return this.fieldName;
  }
  
  public void setFieldName(String fieldName) {
    this.fieldName = fieldName;
  }
  
  public boolean isFormField() {
    return this.isFormField;
  }
  
  public void setFormField(boolean state) {
    this.isFormField = state;
  }
  
  public OutputStream getOutputStream() throws IOException {
    if (this.dfos == null) {
      File outputFile = getTempFile();
      this.dfos = new DeferredFileOutputStream(this.sizeThreshold, outputFile);
    } 
    return (OutputStream)this.dfos;
  }
  
  public File getStoreLocation() {
    return this.dfos.getFile();
  }
  
  protected void finalize() {
    File outputFile = this.dfos.getFile();
    if (outputFile != null && outputFile.exists())
      outputFile.delete(); 
  }
  
  protected File getTempFile() {
    File tempDir = this.repository;
    if (tempDir == null)
      tempDir = new File(System.getProperty("java.io.tmpdir")); 
    String fileName = "upload_" + UID + "_" + getUniqueId() + ".tmp";
    File f = new File(tempDir, fileName);
    FileCleaner.track(f, this);
    return f;
  }
  
  private static String getUniqueId() {
    int current, limit = 100000000;
    synchronized (DiskFileItem.class) {
      current = counter++;
    } 
    String id = Integer.toString(current);
    if (current < 100000000)
      id = ("00000000" + id).substring(id.length()); 
    return id;
  }
  
  public String toString() {
    return "name=" + getName() + ", StoreLocation=" + String.valueOf(getStoreLocation()) + ", size=" + getSize() + "bytes, " + "isFormField=" + isFormField() + ", FieldName=" + getFieldName();
  }
  
  private void writeObject(ObjectOutputStream out) throws IOException {
    if (this.dfos.isInMemory()) {
      this.cachedContent = get();
    } else {
      this.cachedContent = null;
      this.dfosFile = this.dfos.getFile();
    } 
    out.defaultWriteObject();
  }
  
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    OutputStream output = getOutputStream();
    if (this.cachedContent != null) {
      output.write(this.cachedContent);
    } else {
      FileInputStream input = new FileInputStream(this.dfosFile);
      IOUtils.copy(input, output);
      this.dfosFile.delete();
      this.dfosFile = null;
    } 
    output.close();
    this.cachedContent = null;
  }
}

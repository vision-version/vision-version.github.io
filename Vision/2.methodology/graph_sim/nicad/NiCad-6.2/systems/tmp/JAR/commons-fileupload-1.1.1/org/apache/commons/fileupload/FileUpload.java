package org.apache.commons.fileupload;

public class FileUpload extends FileUploadBase {
  private FileItemFactory fileItemFactory;
  
  public FileUpload() {}
  
  public FileUpload(FileItemFactory fileItemFactory) {
    this.fileItemFactory = fileItemFactory;
  }
  
  public FileItemFactory getFileItemFactory() {
    return this.fileItemFactory;
  }
  
  public void setFileItemFactory(FileItemFactory factory) {
    this.fileItemFactory = factory;
  }
}

package org.apache.commons.fileupload;

import java.io.File;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

public class DiskFileUpload extends FileUploadBase {
  private DefaultFileItemFactory fileItemFactory;
  
  public DiskFileUpload() {
    this.fileItemFactory = new DefaultFileItemFactory();
  }
  
  public DiskFileUpload(DefaultFileItemFactory fileItemFactory) {
    this.fileItemFactory = fileItemFactory;
  }
  
  public FileItemFactory getFileItemFactory() {
    return this.fileItemFactory;
  }
  
  public void setFileItemFactory(FileItemFactory factory) {
    this.fileItemFactory = (DefaultFileItemFactory)factory;
  }
  
  public int getSizeThreshold() {
    return this.fileItemFactory.getSizeThreshold();
  }
  
  public void setSizeThreshold(int sizeThreshold) {
    this.fileItemFactory.setSizeThreshold(sizeThreshold);
  }
  
  public String getRepositoryPath() {
    return this.fileItemFactory.getRepository().getPath();
  }
  
  public void setRepositoryPath(String repositoryPath) {
    this.fileItemFactory.setRepository(new File(repositoryPath));
  }
  
  public List parseRequest(HttpServletRequest req, int sizeThreshold, long sizeMax, String path) throws FileUploadException {
    setSizeThreshold(sizeThreshold);
    setSizeMax(sizeMax);
    setRepositoryPath(path);
    return parseRequest(req);
  }
}

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.vfs2.provider.smb;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.apache.commons.vfs2.FileName;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileType;
import org.apache.commons.vfs2.RandomAccessContent;
import org.apache.commons.vfs2.UserAuthenticationData;
import org.apache.commons.vfs2.provider.AbstractFileName;
import org.apache.commons.vfs2.provider.AbstractFileObject;
import org.apache.commons.vfs2.util.RandomAccessMode;
import org.apache.commons.vfs2.util.UserAuthenticatorUtils;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;


/**
 * A file in an SMB file system.
 */
public class SmbFileObject extends AbstractFileObject<SmbFileSystem> {

    DiskShare diskShare;
    private File sambaFile;
    Directory sambaDirectory;
    String filePath;
    SmbFileName smbFileName;


    /**
     * @param name the file name - muse be an instance of {@link AbstractFileName}
     * @param fs   the file system
     * @throws ClassCastException if {@code name} is not an instance of {@link AbstractFileName}
     */
    protected SmbFileObject(final AbstractFileName name, final SmbFileSystem fileSystem) throws FileSystemException {
        super(name, fileSystem);
        // this.fileName = UriParser.decode(name.getURI());
    }

    /**
     * Attaches this file object to its file resource.
     */
    @Override
    protected void doAttach() throws Exception {
        // Defer creation of the SmbFile to here
        if (sambaFile == null) {
            sambaFile = createSmbFile(getName());
        }

        if (sambaDirectory == null ){
            createSmbFile( getName());
        }
    }

    @Override
    protected void doDetach() throws Exception {
        // file closed through content-streams
        sambaDirectory = null;
        sambaFile = null;
    }

    private File createSmbFile(final FileName fileName)
            throws Exception {


        smbFileName = (SmbFileName) fileName;

        filePath = fileName.getBaseName();

        UserAuthenticationData authData = null;

        try {
            authData = UserAuthenticatorUtils.authenticate(getFileSystem().getFileSystemOptions(),
                    SmbFileProvider.AUTHENTICATOR_TYPES);

            SMBClient client = new SMBClient();
            Connection connection = client.connect(((SmbFileName) fileName).getHostName()); // 192.168.43.82

            String userName = UserAuthenticatorUtils.toString(UserAuthenticatorUtils
                    .getData(authData, UserAuthenticationData.USERNAME,
                            UserAuthenticatorUtils.toChar(smbFileName.getUserName())));

            char[] password = UserAuthenticatorUtils.getData(authData, UserAuthenticationData.PASSWORD,
                    UserAuthenticatorUtils.toChar(smbFileName.getPassword()));

            String domain = UserAuthenticatorUtils.toString(UserAuthenticatorUtils
                    .getData(authData, UserAuthenticationData.DOMAIN,
                            UserAuthenticatorUtils.toChar(smbFileName.getDomain())));

            AuthenticationContext authenticationContext = new AuthenticationContext(userName, password, domain);

            Session session = connection.authenticate(authenticationContext);

            // Connect to Share
            diskShare = (DiskShare) session.connectShare(((SmbFileName) fileName).getShare());

            // DiskShare diskShare = (DiskShare) session.connectShare(fileName.getBaseName());


            //sambaFileDiskEntry = diskShare.

            if ( ! filePath.isEmpty()) {

                String  nameOFtheFile = smbFileName.getBaseName();
                if ( !diskShare.fileExists( nameOFtheFile) ){
                    sambaFile = diskShare.openFile(filePath, EnumSet.of(AccessMask.FILE_WRITE_DATA),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE,
                            EnumSet.noneOf(SMB2CreateOptions.class));
                } else {
                    sambaFile = diskShare.openFile(filePath, EnumSet.of(AccessMask.FILE_READ_DATA),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN,
                            EnumSet.noneOf(SMB2CreateOptions.class));
                }

            } else {
                sambaDirectory = diskShare.openDirectory(filePath, EnumSet.of(AccessMask.FILE_WRITE_DATA),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN,
                        EnumSet.noneOf(SMB2CreateOptions.class));
            }

            return sambaFile;

        } finally {
            UserAuthenticatorUtils.cleanup(authData); // might be null
        }
    }


    @Override protected FileType doGetType() throws Exception {

        String  fileName = smbFileName.getBaseName();
        if (diskShare.fileExists( fileName)) {
            return FileType.FILE;
        } else if (diskShare.folderExists( fileName)) {
            return FileType.FOLDER;
        }

        if (!diskShare.fileExists( fileName ) || !diskShare.folderExists( fileName ) ) {
            return FileType.IMAGINARY;
        }

        throw new FileSystemException("vfs.provider.smb/get-type.error", getName());
    }

    @Override protected String[] doListChildren() throws Exception {

        String  fileName = smbFileName.getBaseName();
        if ( !diskShare.folderExists( fileName)) {
            return null;
        }

        String[] list  = new String[diskShare.list(fileName).size() - 2];

        int index =0;
        for ( FileIdBothDirectoryInformation f : diskShare.list(fileName)  ){

            if (  f.getFileName().equals(".") || f.getFileName().equals("..") ){
                continue;
            }
            list[index] = f.getFileName();
            index++;
        }

        return     list;
    }


    /**
     * Determines if this file is hidden.
     */
    @Override
    protected boolean doIsHidden() throws Exception
    {
        return false;
    }

    /**
     * Deletes the file.
     */
    @Override
    protected void doDelete() throws Exception {

        diskShare.rm(filePath);
    }

    @Override
    protected void doRename(FileObject newfile) throws Exception
    {
      //  do nothin
        int i=0;
    }


    /**
     * Creates this file as a folder.
     */
    @Override
    protected void doCreateFolder() throws Exception {
        int i =5;
    }

    @Override protected long doGetContentSize() throws Exception {
        return 0;
    }

    /**
     * Returns the last modified time of this file.
     */
    @Override
    protected long doGetLastModifiedTime() throws Exception {
        return 0;
    }

    /**
     * Creates an input stream to read the file content from.
     */
    @Override
    protected InputStream doGetInputStream() throws Exception {

      return  sambaFile.getInputStream( );
    }

    /**
     * Creates an output stream to write the file content to.
     */
    @Override
    protected OutputStream doGetOutputStream(final boolean bAppend) throws Exception {

        return sambaFile.getOutputStream();

    }

    /**
     * random access
     */
    @Override
    protected RandomAccessContent doGetRandomAccessContent(final RandomAccessMode mode) throws Exception {
        int i=0 ;
        return null;
    }

    @Override
    protected boolean doSetLastModifiedTime(final long modtime) throws Exception {

        return true;
    }

}

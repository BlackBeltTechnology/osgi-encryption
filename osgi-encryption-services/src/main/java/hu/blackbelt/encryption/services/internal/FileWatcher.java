package hu.blackbelt.encryption.services.internal;

/*-
 * #%L
 * OSGi encryption services
 * %%
 * Copyright (C) 2018 - 2023 BlackBelt Technology
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;

@Slf4j
public class FileWatcher implements Runnable {

    final Path path;
    final Path dir;

    private volatile boolean shutdown = false;

    public FileWatcher(final String path) {
        this.path = Paths.get(path);
        dir = this.path.getParent();
    }

    @Override
    public void run() {
        if (log.isDebugEnabled()) {
            log.debug("Starting file watcher: " + path);
        }

        try (final WatchService watchService = path.getFileSystem().newWatchService()) {
            dir.register(watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

            while (!shutdown) {
                final WatchKey watchKey = watchService.take();

                // poll for file system events on the WatchKey
                for (final WatchEvent<?> event : watchKey.pollEvents()) {
                    final Path eventPath = dir.resolve((Path) event.context());

                    if (!path.equals(eventPath)) {
                        continue;
                    }

                    final WatchEvent.Kind<?> kind = event.kind();
                    if (kind.equals(StandardWatchEventKinds.ENTRY_CREATE)) {
                        onCreate(eventPath);
                    } else if (kind.equals(StandardWatchEventKinds.ENTRY_DELETE)) {
                        onDelete(eventPath);
                    } else if (kind.equals(StandardWatchEventKinds.ENTRY_MODIFY)) {
                        onModify(eventPath);
                    }
                }

                // if the watched directed gets deleted, get out of run method
                if (!watchKey.reset()) {
                    if (log.isDebugEnabled()) {
                        log.debug("File watcher is not longer valid, stop it");
                    }
                    watchKey.cancel();
                    break;
                }
            }
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void stop() {
        if (log.isDebugEnabled()) {
            log.debug("Stopping file watcher: " + path);
        }
        shutdown = true;
    }

    protected void onCreate(final Path path) {
        if (log.isTraceEnabled()) {
            log.trace("Created file: " + path);
        }
    }

    protected void onModify(final Path path) {
        if (log.isTraceEnabled()) {
            log.trace("Modified file: " + path);
        }
    }

    protected void onDelete(final Path path) {
        if (log.isTraceEnabled()) {
            log.trace("Deleted file: " + path);
        }
    }
}

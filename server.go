/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"encoding/base64"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/aliasservergo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/bcnetgo"
	"github.com/AletheiaWareLLC/colourgo"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"log"
	"net/http"
	"os"
	"path"
	"time"
)

func main() {
	rootDir, err := bcgo.GetRootDirectory()
	if err != nil {
		log.Println(err)
		return
	}
	//log.Println("Root Dir:", rootDir)

	logFile, err := bcgo.SetupLogging(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	defer logFile.Close()
	//log.Println("Log File:", logFile.Name())

	cacheDir, err := bcgo.GetCacheDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	//log.Println("Cache Dir:", cacheDir)

	cache, err := bcgo.NewFileCache(cacheDir)
	if err != nil {
		log.Println(err)
		return
	}

	network := &bcgo.TcpNetwork{}

	node, err := bcgo.GetNode(rootDir, cache, network)
	if err != nil {
		log.Println(err)
		return
	}

	aliases := aliasgo.OpenAliasChannel()
	if err := bcgo.LoadHead(aliases, cache, network); err != nil {
		log.Println(err)
	}
	if err := bcgo.Pull(aliases, cache, network); err != nil {
		log.Println(err)
	}
	node.AddChannel(aliases)

	listener := &bcgo.PrintingMiningListener{os.Stdout}

	// Serve Block Requests
	go bcnetgo.Bind(bcgo.PORT_GET_BLOCK, bcnetgo.BlockPortHandler(cache, network))
	// Serve Head Requests
	go bcnetgo.Bind(bcgo.PORT_GET_HEAD, bcnetgo.HeadPortHandler(cache, network))
	// Serve Block Updates
	go bcnetgo.Bind(bcgo.PORT_BROADCAST, bcnetgo.BroadcastPortHandler(cache, network, func(name string) (bcgo.Channel, error) {
		return node.GetChannel(name)
	}))

	// Redirect HTTP Requests to HTTPS
	go http.ListenAndServe(":80", http.HandlerFunc(bcnetgo.HTTPSRedirect))

	// Serve Web Requests
	mux := http.NewServeMux()
	mux.HandleFunc("/", bcnetgo.StaticHandler)
	aliasTemplate, err := template.ParseFiles("html/template/alias.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/alias", aliasservergo.AliasHandler(aliases, cache, network, aliasTemplate))
	aliasRegistrationTemplate, err := template.ParseFiles("html/template/alias-register.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/alias-register", aliasservergo.AliasRegistrationHandler(aliases, node, listener, aliasRegistrationTemplate))
	blockTemplate, err := template.ParseFiles("html/template/block.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/block", bcnetgo.BlockHandler(cache, network, blockTemplate))
	channelTemplate, err := template.ParseFiles("html/template/channel.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/channel", bcnetgo.ChannelHandler(cache, network, channelTemplate))
	channelListTemplate, err := template.ParseFiles("html/template/channel-list.html")
	if err != nil {
		log.Println(err)
		return
	}
	mux.HandleFunc("/channels", bcnetgo.ChannelListHandler(cache, network, channelListTemplate, node.GetChannels))
	mux.HandleFunc("/keys", bcnetgo.KeyShareHandler(make(bcnetgo.KeyShareStore), 2*time.Minute))
	mux.HandleFunc("/canvas", CanvasHandler(node))
	mux.HandleFunc("/stripe-webhook", bcnetgo.StripeWebhookHandler)
	registrationTemplate, err := template.ParseFiles("html/template/colour-register.html")
	if err != nil {
		log.Println(err)
		return
	}
	publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY")
	mux.HandleFunc("/colour-register", bcnetgo.RegistrationHandler(aliases, node, listener, registrationTemplate, publishableKey))
	subscriptionTemplate, err := template.ParseFiles("html/template/colour-subscribe.html")
	if err != nil {
		log.Println(err)
		return
	}
	productId := os.Getenv("STRIPE_PRODUCT_ID")
	planId := os.Getenv("STRIPE_PLAN_ID")
	mux.HandleFunc("/colour-subscribe", bcnetgo.SubscriptionHandler(aliases, node, listener, subscriptionTemplate, "/subscribed.html", productId, planId))
	certDir, err := bcgo.GetCertificateDirectory(rootDir)
	if err != nil {
		log.Println(err)
		return
	}
	// Serve HTTPS Requests
	log.Println(http.ListenAndServeTLS(":443", path.Join(certDir, "fullchain.pem"), path.Join(certDir, "privkey.pem"), mux))
}

func CanvasHandler(node *bcgo.Node) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			query := r.URL.Query()
			var canvas string
			if results, ok := query["canvas"]; ok && len(results) == 1 {
				canvas = results[0]
			}
			log.Println("Canvas", canvas)
			if len(canvas) > 0 {
				hash, err := base64.RawURLEncoding.DecodeString(canvas)
				if err != nil {
					log.Println(err)
					return
				}
				canvases := colourgo.OpenCanvasChannel()
				if err := bcgo.LoadHead(canvases, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
				if err := bcgo.Pull(canvases, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
				if err := colourgo.GetCanvas(canvases, node.Cache, node.Network, "", nil, hash, func(entry *bcgo.BlockEntry, key []byte, c *colourgo.Canvas) error {
					// TODO Draw image of canvas
					i := image.NewRGBA(image.Rect(0, 0, int(c.Width), int(c.Height)))
					blue := color.RGBA{0, 0, 255, 255}
					draw.Draw(i, i.Bounds(), &image.Uniform{blue}, image.ZP, draw.Src)

					var img image.Image = i
					buffer := new(bytes.Buffer)
					if err := jpeg.Encode(buffer, img, nil); err != nil {
						return err
					}

					t, err := template.ParseFiles("html/template/canvas.html")
					if err != nil {
						return err
					}
					data := struct {
						Hash      string
						Timestamp string
						Name      string
						Width     uint32
						Height    uint32
						Depth     uint32
						Mode      string
						Image     string
					}{
						Hash:      canvas,
						Timestamp: bcgo.TimestampToString(entry.Record.Timestamp),
						Name:      c.Name,
						Width:     c.Width,
						Height:    c.Height,
						Depth:     c.Depth,
						Mode:      c.Mode.String(),
						Image:     base64.StdEncoding.EncodeToString(buffer.Bytes()),
					}
					log.Println("Data", data)
					err = t.Execute(w, data)
					if err != nil {
						return err
					}
					return nil
				}); err != nil {
					log.Println(err)
					return
				}
			} else {
				t, err := template.ParseFiles("html/template/canvas-list.html")
				if err != nil {
					log.Println(err)
					return
				}
				type TemplateCanvas struct {
					Hash      string
					Name      string
					Timestamp string
					Width     uint32
					Height    uint32
					Depth     uint32
					Mode      string
				}
				cs := make([]TemplateCanvas, 0)
				canvases := colourgo.OpenCanvasChannel()
				if err := bcgo.LoadHead(canvases, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
				if err := bcgo.Pull(canvases, node.Cache, node.Network); err != nil {
					log.Println(err)
				}
				if err := colourgo.GetCanvas(canvases, node.Cache, node.Network, "", nil, nil, func(entry *bcgo.BlockEntry, key []byte, c *colourgo.Canvas) error {
					cs = append(cs, TemplateCanvas{
						Hash:      base64.RawURLEncoding.EncodeToString(entry.RecordHash),
						Timestamp: bcgo.TimestampToString(entry.Record.Timestamp),
						Name:      c.Name,
						Width:     c.Width,
						Height:    c.Height,
						Depth:     c.Depth,
						Mode:      c.Mode.String(),
					})
					return nil
				}); err != nil {
					log.Println(err)
					return
				}
				data := struct {
					Canvas []TemplateCanvas
				}{
					Canvas: cs,
				}
				log.Println("Data", data)
				err = t.Execute(w, data)
				if err != nil {
					log.Println(err)
					return
				}
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}

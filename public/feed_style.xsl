<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
  <xsl:output method="html" version="1.0" encoding="UTF-8" indent="yes"/>
  <xsl:template match="/">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <title><xsl:value-of select="/rss/channel/title"/> RSS Feed</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1"/>
        <meta charset="UTF-8"/>
        
        <link type="text/css" rel="stylesheet" href="http://0.0.0.0/css/styles.6f84514ad632600fba315252a38e35f30218f3d5ec268c1236f62782176917002e704c2b142a2d949bd831c6feabc3d6db35a3c6d6e151b839b9fe80cc19fa4f.css" integrity="sha512-b4RRStYyYA+6MVJSo4418wIY89XsJowSNvYnghdpFwAucEwrFCotlJvYMcb+q8PW2zWjxtbhUbg5uf6AzBn6Tw==" />
        <style>
          .aboutfeeds {
            margin: 24px 0; padding: 12px;
            border: 2px solid var(--default_accent);
            background-color: var(--default_hl_bg)
          }
          .head {
            display: flex;
            flex-direction: row;
            align-items: center;
          }
          .logo {
            width: 50px;
            max-height: 50px;
            border-radius: 5px;
            display: block;
            margin-right: 10px;
          }
          .rssLogo {
            display: block;
            margin-right: 10px;
          }
          header h1 {
            display: flex;
            flex-direction: row;
            align-items: center;
          }
        </style>
      </head>
      <body>
        <header>
          <h1>
            <svg class="rssLogo" width="32" height="32" version="1.1" viewBox="0 0 32 32"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path fill="#ff7800"
                d="M 4.9970764,0 H 26.997124 C 29.767161,0 31.9971,2.2300144 31.9971,4.9999764 V 27.000024 C 31.9971,29.770061 29.767086,32 26.997124,32 H 4.9970764 C 2.2270388,32 -0.0029,29.769986 -0.0029,27.000024 V 4.9999764 C -0.0029,2.2299388 2.2271144,0 4.9970764,0 Z"
              />
              <path fill="#ffffff"
                d="m 10.652345,21.357209 q 0.794754,0.795468 0.794754,1.931828 0,1.120137 -0.794754,1.915672 -0.7947706,0.795468 -1.9301364,0.795468 -1.1353653,0 -1.930136,-0.795468 -0.7947708,-0.795467 -0.7947708,-1.915672 0,-1.136377 0.7947708,-1.931828 0.7947707,-0.811691 1.930136,-0.811691 1.1353658,0 1.9301364,0.811691 z m 8.077348,3.668942 q 0.01682,0.405854 -0.243305,0.68182 -0.259516,0.292205 -0.664997,0.292205 h -1.913994 q -0.373047,0 -0.632562,-0.22728 -0.243306,-0.2435 -0.259515,-0.584427 -0.324402,-3.263021 -2.643912,-5.56829 Q 10.068158,17.298754 6.8243058,16.990274 6.4674686,16.957811 6.2241796,16.714291 5.9971,16.454549 5.9971,16.097399 v -1.915673 q 0,-0.422077 0.2919482,-0.681819 0.2433052,-0.22728 0.6163522,-0.22728 h 0.081045 q 2.2544878,0.178576 4.3307416,1.136377 2.076086,0.957803 3.681871,2.581269 1.621977,1.623399 2.579007,3.701423 0.97319,2.061749 1.151609,4.334538 z m 7.266385,0.01614 q 0.01682,0.405853 -0.243305,0.681819 -0.259516,0.275984 -0.665013,0.275984 h -2.027493 q -0.356836,0 -0.632578,-0.243502 -0.275724,-0.243504 -0.29195,-0.600637 -0.16226,-3.051983 -1.427332,-5.811809 -1.26514,-2.759827 -3.292615,-4.772772 Q 15.404609,12.542104 12.6472,11.275872 9.9061004,9.9933838 6.8567915,9.8310488 6.4999709,9.8148927 6.2404563,9.5550662 5.9971503,9.2953236 5.9971503,8.9219502 V 6.8926809 q 0,-0.3896138 0.2919481,-0.6493564 Q 6.5324037,5.9998227 6.905451,5.9998227 h 0.048594 q 3.730464,0.1948173 7.120435,1.7207897 3.406113,1.5097508 6.033714,4.1558116 2.660054,2.629906 4.168482,6.039004 1.524655,3.409099 1.719283,7.126678 z"
              />
            </svg>
            <xsl:value-of select="/rss/channel/title"/>
          </h1>
          <div class="aboutfeeds">
            <p>This is a web feed, also known as an RSS feed. <strong>Subscribe</strong> by copying the URL into your RSS reader.</p>
          </div>
          <div class="head">
            <div class="avatar">
              <img class="logo" src="<no value>" alt="Site Logo"/>
            </div>
            <div class="description">
              <p><xsl:value-of select="/rss/channel/description"/></p>
              <p><a hreflang="en"><xsl:attribute name="href"><xsl:value-of select="/rss/channel/link"/></xsl:attribute>Visit Website &#x2192;</a></p>
            </div>
          </div>
        </header>
        <div id="content">
          <main>
            <h2>📄 Recent Posts</h2>
            <xsl:for-each select="/rss/channel/item">
              <article>
                <h3><a target="_blank"><xsl:attribute name="href"><xsl:value-of select="link"/></xsl:attribute><xsl:value-of select="title"/></a></h3>
                <footer>Published: <time><xsl:value-of select="pubDate" /></time></footer>
              </article>
            </xsl:for-each>
          </main>
        </div>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>

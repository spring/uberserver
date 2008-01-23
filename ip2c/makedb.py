"""
/*****************************************************************************
//
// IP2Country binary database maker
//
// Copyright (C) 2004  L. Petersen, Weird Silence, www.weirdsilence.net
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//
*****************************************************************************/
"""

from struct import pack, calcsize

def long2ip( longip ):
    b4 = ( longip >> 24 ) & 255
    b3 = ( longip >> 16 ) & 255
    b2 = ( longip >> 8  ) & 255
    b1 = longip & 255
    return ( b4, b3, b2, b1 )

def readFile( filename, isGeo ):
    f = file( filename, 'r' )
    lines = f.readlines()
    f.close()

    f = file( 'ip2cntry.dat', 'wb+' )
    # Write magic
    f.write( 'ip2c' )
    # Reserve index position
    f.write( pack( '<i', 0 ) )
    
    min = None
    countries = []
    cnt = 0
    topidx = {}
    minip = 0
    maxip = 0
    for line in lines:
        cnt += 1
        try:
            line = line.replace( '"', '' )
            if isGeo:
                tmp, tmp, start, end, two, tmp = line.split( ',', 5 )
            else:
                # The CSV is start,end,twochar,threechar,country name
                # We don't use threechar and country
                start, end, two, tmp, tmp = line.split( ',', 4 )
            start = long( start )
            end = long( end )
            if two not in countries:
                # New country
                countries.append( two )
            countryidx = countries.index( two )
            # Write record
            f.write( pack( '<LLH', start, end, countryidx ) )

            # Check out the A class
            aclassStart, tmp, tmp, tmp = long2ip( start )
            aclassEnd, tmp, tmp, tmp = long2ip( end )
            for i in range( aclassStart, aclassEnd + 1 ):
                if i not in topidx:
                    # This is an A class we don't have yet
                    # Give it the current record number
                    topidx[ i ] = cnt
            if min is None:
                # Smallest IP and A class
                min = start
                minip = aclassStart

            # Max IP and A class
            max = end
            maxip = aclassEnd
        except ValueError:
            # Hmm some error, print the line
            print line
            cnt -= 1
        if cnt % 15000 == 0:
            print "Please wait..."
    # We're done, get position of end - Where to begin the index
    idx = f.tell()
    # Write index
    f.write( pack( '<LLLBH', cnt, min, max, calcsize( '<LLH' ), len( countries ) ) )
    # Write country codes
    for country in countries:
        f.write( country )
    # Write smallest and largest A class
    f.write( pack( '<BB', minip, maxip ) )
    lastpos = 0
    for i in range( minip, maxip + 1 ):
        # Write record positions of all A classes
        if i in topidx:
            pos = topidx[ i ]
            lastpos = pos
        else:
            pos = -lastpos
        f.write( pack( '<l', pos ) )
    # Update the file header and record the position of our index
    f.seek( 4 )
    f.write( pack( '<i', idx ) )
    f.close()
    # Done!
    print cnt, "records. Countries:", len( countries ), "Min:", min, "Max:", max
    print "A class ", minip, "-", maxip

if __name__ == '__main__':
    from sys import argv
    if len( argv ) == 2 and argv[ 1 ] != '-g':
        readFile( argv[ 1 ], False )
    elif len( argv ) == 3:
        readFile( argv[2], True )
    else:
        print "makedb.py [-g] csvfile"
        print " -g specifies GeoIP Free CSV"
        print ""
        print "Get the latest IP-to-Country CSV file from here:"
        print " http://ip-to-country.webhosting.info/downloads/ip-to-country.csv.zip"
        print ""
        print "Get the latest GeoIP CSV file from here:"
        print " http://www.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip"
        print ""

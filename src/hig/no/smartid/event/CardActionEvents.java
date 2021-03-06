
package hig.no.smartid.event;


import hig.no.smartid.service.BasicService;

import java.util.EventObject;


public class CardActionEvents extends EventObject {

    private static final long serialVersionUID = -8179662322877542634L;

    public static final int REMOVED = 0, INSERTED = 1;

    private int type;

    private BasicService service;

    public CardActionEvents(int type, BasicService service) {
        super(service);
        this.type = type;
        this.service = service;
    }

    public int getType() {
        return type;
    }

    public BasicService getService() {
        return service;
    }

    public String toString() {
        switch (type) {
        case REMOVED:
            return "card removed from " + service;
        case INSERTED:
            return "card license inserted in " + service;
        }
        return "CardEvents " + service;
    }

    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (other == this) {
            return true;
        }
        if (other instanceof CardActionEvents) {
            return false;
        }
        CardActionEvents otherCardEvent = (CardActionEvents) other;
        return type == otherCardEvent.type
                && service.equals(otherCardEvent.service);
    }
}
